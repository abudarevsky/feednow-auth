"""Domain-oriented storage protocol and error vocabulary. The 28 operations use domain entities and typed results; adapter details remain behind this boundary.

Current behavior and invariants: ``docs/storage.md``."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from app.models.api_key import ApiKey, KeyId
from app.models.audit_event import AuditEvent
from app.models.enums import ApplicationRole, IdentityProvider, MembershipRole
from app.models.external_identity import ExternalIdentity, ProviderTenant
from app.models.ids import ApiKeyId, OrganizationId, ProviderSubject, UserId
from app.models.membership import Membership
from app.models.organization import Organization, OrganizationSlug
from app.models.organization_onboarding import OrganizationOnboardingRequest
from app.models.pagination import Page, PageParams
from app.models.service_authorization import ServiceAuthorizationCode
from app.models.session import AppSession, OAuthLoginState
from app.models.timestamps import UtcDatetime
from app.models.user import User

# ---------------------------------------------------------------------------
# Domain error vocabulary
# ---------------------------------------------------------------------------


class StorageError(Exception):
    """Base class for every domain-level storage failure.

    Adapters raise only subclasses of this type; driver-specific exceptions
    (``sqlite3.IntegrityError``, ``botocore.exceptions.ClientError``, ...)
    must be translated inside the adapter and must never propagate above this
    contract. ``args[0]`` is a human-readable, log-safe message: it must never
    embed SQL, table/row dumps, connection strings, or secret material.
    """


class EntityNotFoundError(StorageError):
    """The requested entity does not exist.

    Raised by every ``get_*``/``revoke_api_key`` miss and by
    :meth:`Storage.get_user_by_external_identity` — an identity lookup miss is
    *not* a ``None`` return; raising is identity implementation "needs provisioning" signal.
    Whether HTTP answers 404 or 204 is organization+ mapping work.
    """


class DuplicateEntityKind(StrEnum):
    """Stable discriminator for :class:`DuplicateEntityError` (domain model contract/credential contract).

    Additive vocabulary: renaming or removing a value is a contract change
    requiring a contract revision. ``entity_id`` covers PRIMARY KEY (``id``)
    collisions on any stored record; the remaining values name the
    domain-uniqueness constraints (external-identity tuple, membership pair,
    organization slug, user email, ``api_keys.key_id`` credential segment).
    ``USER_EMAIL`` is retained per this enum's own frozen additive-vocabulary
    rule but is **never raised** from application-role on: shadow registration made
    equal emails valid separate users, so email is no longer a uniqueness
    constraint and no adapter may translate a violation into this kind.
    """

    ENTITY_ID = "entity_id"
    EXTERNAL_IDENTITY = "external_identity"
    MEMBERSHIP = "membership"
    ORGANIZATION_SLUG = "organization_slug"
    USER_EMAIL = "user_email"
    API_KEY_ID = "api_key_id"


class DuplicateEntityError(StorageError):
    """A write violated a uniqueness constraint.

    ``kind`` is the machine-readable half callers and tests branch on; the
    message is human-readable only. Adapters translate the driver's integrity
    error into exactly one of the :class:`DuplicateEntityKind` values, so no
    SQL constraint name or index text leaks above the adapter.
    """

    def __init__(self, kind: DuplicateEntityKind | str, message: str | None = None) -> None:
        #: One of the stable :class:`DuplicateEntityKind` values. Adapters
        #: must pass ``"entity_id"`` for primary-key collisions.
        self.kind: DuplicateEntityKind = DuplicateEntityKind(kind)
        super().__init__(message or f"duplicate entity: {self.kind.value}")


class DuplicateExternalIdentityError(DuplicateEntityError):
    """Concurrent-provisioning signal raised by :meth:`Storage.provision_user`.

    The external-identity tuple ``(provider, provider_subject,
    provider_tenant)`` is the **sole** race/convergence key (application-role): in
    identity contract's concurrent-first-login race both attempts carry the same
    tuple, and the loser's UNIQUE violation on it surfaces as this error
    (kind is pinned to ``external_identity``). Email is no longer part of
    the race story — two attempts sharing an address but carrying distinct
    identity tuples are two legitimate separate users, never a conflict.

    ``existing_user_id`` is the winner's ``usr_`` identity when the adapter can
    resolve it after rolling back, else ``None`` — so identity converges
    without a second query. Every failure path is fully rolled back.
    """

    def __init__(
        self,
        *,
        existing_user_id: UserId | None = None,
        message: str | None = None,
    ) -> None:
        super().__init__(DuplicateEntityKind.EXTERNAL_IDENTITY, message)
        #: Winner's user identity when resolvable by the adapter, else ``None``.
        self.existing_user_id: UserId | None = existing_user_id


class ReferenceNotFoundError(StorageError):
    """A write referenced a parent row that does not exist.

    Covers identity→user, membership→organization+user,
    api_key→organization+creator, and audit→organization. Adapters enforce it
    regardless of mechanism (SQLite foreign keys, DynamoDB conditional writes).
    """


class InvalidCursorError(StorageError):
    """A pagination cursor is malformed, tampered with, or foreign.

    Cursors are opaque and adapter-generated; a caller-supplied value that
    does not decode raises this and **never** a raw ``ValueError``,
    ``binascii.Error``, or driver error. A cursor issued for one list is
    invalid for another (the encoded position carries a list-scope tag).
    """


class LastActiveAdministratorError(StorageError):
    """Additive admin refusal raised by
    :meth:`Storage.transition_application_role`.

    A demotion ``ADMIN → USER`` whose target is ``ACTIVE`` is refused when no
    **other** ``ACTIVE`` admin user exists: the system must never be left
    without an active application administrator (contract 13 required
    behavior 3). The refusal is fully rolled back — the target keeps
    ``ADMIN``, no timestamp moves, and no audit row is written. A demotion of
    a ``DISABLED`` admin never raises it (the active-admin count cannot
    change). How HTTP/CLI maps this refusal is caller-side work, never a
    storage concern.
    """


# ---------------------------------------------------------------------------
# Compound-operation results
# ---------------------------------------------------------------------------


class ProvisionedUser(BaseModel):
    """Frozen result bundle returned by :meth:`Storage.provision_user`.

    **Caller-echo contract:** the bundle carries the caller-supplied domain
    objects *unchanged*. Storage mints nothing and does not re-read what it
    wrote — there is no read-back, no id/timestamp regeneration, and no
    adapter row leakage. Persistence is proven by the conformance suite's read
    cases and, for audit rows, by the duplicate-append proof; DynamoDB must
    not add reads to honor this shape.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    user: User
    identity: ExternalIdentity
    organization: Organization
    membership: Membership
    audit_events: tuple[AuditEvent, ...]


class ProvisionedOrganization(BaseModel):
    """Frozen result bundle returned by :meth:`Storage.provision_organization`.

    **Caller-echo contract:** identical discipline to :class:`ProvisionedUser`
    — the bundle carries the caller-supplied domain objects *unchanged*;
    storage mints nothing and does not re-read what it wrote. Persistence is
    proven by the conformance suite's read cases and, for audit rows, by the
    duplicate-append proof; DynamoDB must not add reads to honor this shape.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    organization: Organization
    membership: Membership
    audit_events: tuple[AuditEvent, ...]


class RoleTransitionOutcome(StrEnum):
    """Stable discriminator for :meth:`Storage.transition_application_role`.

    ``TRANSITIONED`` means the role write and its audit event committed in
    one transaction; ``NO_CHANGE`` is the idempotent no-op (the stored role
    already equals the requested role) with **zero writes** and the supplied
    audit event not persisted. A third outcome cannot exist while
    :class:`~app.models.enums.ApplicationRole` is the closed two-value
    vocabulary — a CAS miss on ``expected_role`` can only mean stored equals
    ``new_role`` (contract tripwire: adding a third role requires revisiting
    this operation and this enum).
    """

    TRANSITIONED = "transitioned"
    NO_CHANGE = "no_change"


@dataclass(frozen=True)
class RoleTransition:
    """Frozen result returned by :meth:`Storage.transition_application_role`.

    ``user`` is the final stored record: on ``TRANSITIONED`` the updated user
    (``new_role`` + caller-supplied ``updated_at``, read back inside the
    committing transaction — the :meth:`Storage.revoke_api_key` read-back
    precedent), on ``NO_CHANGE`` the untouched stored user. ``outcome`` tells
    the caller whether the audit event was persisted; a ``NO_CHANGE`` caller
    must **not** re-append (the adapter already skipped it).
    """

    user: User
    outcome: RoleTransitionOutcome


# ---------------------------------------------------------------------------
# The protocol groups entity storage, provisioning, authorization, sessions,
# and registered-service authorization-code operations.
# ---------------------------------------------------------------------------


@runtime_checkable
class Storage(Protocol):
    """Domain-oriented storage operations (storage contract/storage contract).

    Implementations are adapters (``app.storage.sqlite``, later
    ``app.storage.dynamodb``); application code is typed against this Protocol
    only and obtains instances through a documented factory, never by
    constructing an adapter.

    Every method is synchronous. Every ``create_*``/``append_*`` accepts a
    fully formed domain entity and returns the stored entity unchanged
    (storage mints no ids or timestamps); every failure is a
    :class:`StorageError` subclass as pinned per method below.
    """

    # -- Users and external identities -------------------------------------

    def create_user(self, user: User) -> User:
        """Persist a new user.

        Email is **not** a uniqueness constraint from application-role on: two
        distinct ``usr_`` identities may carry the same address (shadow
        registration), so this operation never raises a ``user_email``
        conflict.

        Raises:
            DuplicateEntityError: ``kind="entity_id"`` when ``user.id``
                already exists.
        """
        ...

    def get_user(self, user_id: UserId) -> User:
        """Load a user by ``usr_`` application identity.

        Raises:
            EntityNotFoundError: when no such user exists.
        """
        ...

    def update_user(self, user: User) -> User:
        """Persist caller-owned mutable profile fields and timestamp."""
        ...

    def list_users_by_email(self, email: str) -> list[User]:
        """Exact-match lookup of every user that carries ``email`` (application-role).

        Email is a non-unique exact-lookup field, so this returns a list and
        the consumer must handle zero/one/many results explicitly rather than
        guessing (contract 12 invariant 5). Results are ordered by
        ``(created_at, id)`` ascending — the same deterministic key the
        paginated lists use, with ``id`` the tiebreaker. An unknown address
        returns an empty list and **never** raises
        :class:`EntityNotFoundError` (this is a lookup, not the storage contract resolve
        signal). There is deliberately no pagination cursor: this is a
        documented **bounded** domain operation serving the provisioning and
        administration resolution rules, not a generic adapter query API.
        """
        ...

    def list_users(self) -> list[User]:
        """Return all users ordered by ``(created_at, id)`` for operator reports.

        This read-only administrative operation is intentionally unfiltered;
        callers must not expose it as a public endpoint.
        """
        ...

    def create_external_identity(self, identity: ExternalIdentity) -> ExternalIdentity:
        """Attach a provider identity to an existing user.

        The tuple ``(provider, provider_subject, provider_tenant)`` is unique,
        with ``provider_tenant=None`` normalized so NULL cannot slip past the
        constraint; the stored value reads back as ``None``.

        Raises:
            DuplicateEntityError: ``kind="external_identity"`` for a taken
                tuple, ``kind="entity_id"`` for a taken ``extid_`` record id.
            ReferenceNotFoundError: when ``identity.user_id`` is unknown.
        """
        ...

    def get_user_by_external_identity(
        self,
        *,
        provider: IdentityProvider,
        provider_subject: ProviderSubject,
        provider_tenant: ProviderTenant | None = None,
    ) -> User:
        """Resolve a provider identity to the internal :class:`User`.

        **This method *is* storage contract's ``resolve_external_identity``** — one
        operation, storage contract's name; there is no *separate* ``resolve_external_identity`` method
        on this protocol (the naming mismatch is a contract-revision proposal).

        ``provider_subject`` is a provider-side string (Cognito ``sub``,
        Shopify shop ID) and is never coerced into, or matched against, a
        ``usr_`` application identity. A miss raises and never returns ``None``
        — that exception is identity implementation "needs provisioning" signal.

        Raises:
            EntityNotFoundError: when no identity matches the tuple.
        """
        ...

    # -- Application role administration (Phase 13) ---------------------------
    #
    # Additive Phase 13 surface backing out-of-band administrator
    # bootstrap/revocation. The active-admin guard and the transition are
    # **one** adapter operation (spec 13 required behavior 3): callers must
    # never compose a check-then-write from the reads above.

    def transition_application_role(
        self,
        *,
        user_id: UserId,
        expected_role: ApplicationRole,
        new_role: ApplicationRole,
        updated_at: UtcDatetime,
        audit_event: AuditEvent,
    ) -> RoleTransition:
        """Atomically CAS the user's global ``application_role`` and append
        the caller-formed ``audit_event`` in one transaction (admin).

        Pinned semantics (this docstring **is** the contract-13 storage-transition
        contract; adapters must not reinterpret them):

        - Unknown user → :class:`EntityNotFoundError`.
        - Stored role == ``new_role`` → :class:`RoleTransitionOutcome.NO_CHANGE`
          with **zero writes**: no role update, no timestamp movement, and the
          supplied ``audit_event`` is **not** persisted (idempotent no-op —
          repeated grant/revoke never create duplicate audits). The returned
          :class:`RoleTransition` carries the unchanged stored user.
        - Because :class:`~app.models.enums.ApplicationRole` is a closed
          two-value vocabulary, a CAS miss on ``expected_role`` can only mean
          stored == ``new_role``, so no third outcome exists (tripwire: adding
          a third role requires revisiting this operation).
        - A demotion ``ADMIN → USER`` whose target is ``ACTIVE`` is refused
          with :class:`LastActiveAdministratorError` when no **other**
          ``ACTIVE`` admin user exists, fully rolled back (no role write, no
          audit row). A demotion of a ``DISABLED`` admin skips the guard: the
          active-admin count cannot change.
        - On :class:`RoleTransitionOutcome.TRANSITIONED` the role update and
          the ``audit_event`` append commit in one transaction; the returned
          :class:`User` is the final stored record with ``new_role`` and the
          caller-supplied ``updated_at`` (read-back allowed — the
          :meth:`revoke_api_key` precedent; storage still mints nothing).
        - Audit-parent integrity: when ``audit_event.organization_id`` is not
          ``None`` the transition enforces the same organizations-parent
          guarantee as :meth:`append_audit_event` — SQLite via the existing
          FK failure → :class:`ReferenceNotFoundError` mapping, DynamoDB via
          an additional parent ``ConditionCheck`` inside the same transaction
          (missing parent → :class:`ReferenceNotFoundError` with full
          rollback: no role write, no audit row), closing the race where the
          organization is deleted between the caller's anchor read and commit;
          ``organization_id=None`` → no parent check (the contract keeps
          org-less audits legal).

        **admin replication obligation:** DynamoDB must enforce the same
        all-or-nothing transition, the same no-op/refusal/guard semantics, and
        the same parent check inside its conditional transaction; the
        conformance suite pins the observable behavior, not the mechanism.

        Raises:
            EntityNotFoundError: when no user has that ``usr_`` identity.
            LastActiveAdministratorError: demotion of the last ``ACTIVE``
                admin, fully rolled back.
            ReferenceNotFoundError: unknown ``audit_event.organization_id``
                (when present), fully rolled back.
            DuplicateEntityError: ``kind="entity_id"`` when the ``aud_``
                record id was already appended.
        """
        ...

    # -- Organizations ------------------------------------------------------

    def create_organization(self, organization: Organization) -> Organization:
        """Persist a new organization.

        Raises:
            DuplicateEntityError: ``kind="organization_slug"`` when the slug is
                taken (slug is a constraint, never an identity), or
                ``kind="entity_id"`` when ``organization.id`` already exists.
        """
        ...

    def get_organization(self, organization_id: OrganizationId) -> Organization:
        """Load an organization by ``org_`` identity.

        Raises:
            EntityNotFoundError: when no such organization exists.
        """
        ...

    def update_organization(self, organization: Organization) -> Organization:
        """Persist mutable organization name/slug/status/timestamp fields.

        Raises:
            DuplicateEntityError: ``kind="organization_slug"`` if the new
                slug belongs to another organization.
            EntityNotFoundError: if the organization does not exist.
        """
        ...

    def is_organization_slug_available(
        self,
        slug: OrganizationSlug,
        excluding_organization_id: OrganizationId | None = None,
    ) -> bool:
        """Whether ``slug`` is free globally, optionally ignoring one organization."""
        ...

    def list_user_organizations(
        self,
        user_id: UserId,
        page: PageParams,
    ) -> Page[Organization]:
        """Page through organizations the user belongs to.

        Domain operation, not a join helper: returns only organizations where
        the user holds an **active** membership — ``disabled`` is a suspension
        and hides the organization (organization re-checks roles). Results are
        ordered by ``(created_at, id)`` ascending; ``id`` is the tiebreaker
        that makes keyset traversal deterministic.

        Raises:
            InvalidCursorError: when ``page.cursor`` is malformed, tampered
                with, or was issued for a different list.
        """
        ...

    # -- Memberships --------------------------------------------------------

    def create_membership(self, membership: Membership) -> Membership:
        """Grant a user a role in an organization.

        ``(organization_id, user_id)`` is unique.

        Raises:
            DuplicateEntityError: ``kind="membership"`` for an existing pair,
                ``kind="entity_id"`` for a taken ``mem_`` record id.
            ReferenceNotFoundError: when the organization or the user is
                unknown.
        """
        ...

    def get_membership(self, *, organization_id: OrganizationId, user_id: UserId) -> Membership:
        """Load the membership for one ``(organization, user)`` domain tuple.

        The tuple is the lookup key; the ``mem_`` record id never surfaces
        above storage and is never a lookup key here.

        Raises:
            EntityNotFoundError: when the user is not a member of that
                organization (any status: use this for suspension checks).
        """
        ...

    def list_memberships(
        self,
        organization_id: OrganizationId,
        page: PageParams,
    ) -> Page[Membership]:
        """Page through one organization's memberships (all statuses).

        Strictly organization-scoped: memberships of any other organization
        never appear. Ordered by ``(created_at, id)`` ascending.

        Raises:
            InvalidCursorError: for a malformed, tampered, or foreign cursor.
        """
        ...

    def delete_membership(self, *, organization_id: OrganizationId, user_id: UserId) -> None:
        """Physically remove one ``(organization, user)`` membership.

        Removal is a physical delete (initial pinned ``disabled`` as
        suspension, not removal). Idempotency is *not* provided: a second
        delete of the same pair raises.

        Raises:
            EntityNotFoundError: when no such membership exists.
        """
        ...

    def transfer_organization_owner(
        self,
        *,
        organization_id: OrganizationId,
        former_owner_id: UserId,
        new_owner_id: UserId,
        new_owner_role: MembershipRole,
        audit_event: AuditEvent,
    ) -> None:
        """Atomically promote an active member and demote the former owner.

        Both membership role changes and the supplied audit event commit as
        one transaction. The former owner becomes ``org_admin``.
        """
        ...

    # -- API keys -----------------------------------------------------------

    def create_api_key(self, api_key: ApiKey) -> ApiKey:
        """Persist a new API-key credential row.

        The non-secret credential contract ``key_id`` credential segment is unique. ``scopes``
        round-trip exactly (order and duplicates preserved — normalization is
        API-key domain work). No plaintext secret exists on the model and none
        may be derived or logged here.

        Raises:
            DuplicateEntityError: ``kind="api_key_id"`` when the ``key_id``
                segment is taken, ``kind="entity_id"`` when ``api_key.id``
                already exists.
            ReferenceNotFoundError: when the organization or creating user is
                unknown.
        """
        ...

    def get_api_key(self, api_key_id: ApiKeyId) -> ApiKey:
        """Load a key by its ``key_`` application identity.

        Tenancy is deliberately **not** filtered here: the credential contract verification path
        must resolve the organization *from* the key, so the full row is
        returned regardless of organization and enforcing the API contract org-scoped
        route contract is the API-key service's check of
        ``api_key.organization_id``, not a storage filter.

        ``api_key_id`` is the :class:`~app.models.ids.ApiKeyId` application
        identity — not the API-key credential segment (see
        :meth:`get_api_key_by_key_id`; the collision is also flagged in
        :mod:`app.api.schemas.manifest`).

        Raises:
            EntityNotFoundError: when no such key exists.
        """
        ...

    def get_api_key_by_key_id(self, key_id: KeyId) -> ApiKey:
        """Load a key by the credential contract non-secret ``<key-id>`` credential segment.

        Point lookup on the unique segment inside ``fn_live_<key-id>_<secret>``
        — keyed by :data:`~app.models.api_key.KeyId`, a different type from the
        ``key_`` :class:`~app.models.ids.ApiKeyId` used by
        :meth:`get_api_key`. Returns stored truth: after revocation the row
        still resolves with ``status=revoked`` and ``revoked_at`` set, because
        status is data and rejection is API-key verification work.

        Raises:
            EntityNotFoundError: when no key carries that segment.
        """
        ...

    def list_api_keys(
        self,
        organization_id: OrganizationId,
        page: PageParams,
    ) -> Page[ApiKey]:
        """Page through one organization's API keys (all statuses).

        Strictly organization-scoped. Ordered by ``(created_at, id)``
        ascending.

        Raises:
            InvalidCursorError: for a malformed, tampered, or foreign cursor.
        """
        ...

    def revoke_api_key(self, api_key_id: ApiKeyId, *, revoked_at: UtcDatetime) -> ApiKey:
        """Transition a key ``active → revoked`` (first-write-wins CAS).

        ``revoked_at`` comes from the caller (storage never mints timestamps).
        The update is a compare-and-set: a concurrent or duplicate revocation
        returns the stored key with the **original** ``revoked_at`` preserved —
        an idempotent success, not an error (AGENTS.md requires revocation
        duplicate behavior to be defined and tested). Only the CAS is
        idempotent; absence is absence.

        Raises:
            EntityNotFoundError: when no key has that ``key_`` identity.
        """
        ...

    # -- Audit --------------------------------------------------------------

    def append_audit_event(self, audit_event: AuditEvent) -> None:
        """Append one fully formed audit event (standalone write path).

        Returns ``None`` — storage mints nothing and re-reads nothing, so there
        is nothing to return. identity-05 services use this for events outside
        any compound operation (``membership.removed``, ``api_key.revoked``,
        ...); only provisioning batches go through :meth:`provision_user`.
        ``metadata`` round-trips exactly as JSON. There is no audit read or
        list surface in this capability.

        Raises:
            DuplicateEntityError: ``kind="entity_id"`` when the ``aud_`` record
                id was already appended.
            ReferenceNotFoundError: when ``audit_event.organization_id`` is
                unknown.
        """
        ...

    # -- Compound operations (spec §12) -------------------------------------

    def provision_user(
        self,
        *,
        user: User,
        identity: ExternalIdentity,
        organization: Organization,
        membership: Membership,
        audit_events: Sequence[AuditEvent],
        onboarding_request: OrganizationOnboardingRequest | None = None,
    ) -> ProvisionedUser:
        """Atomically provision user + identity + organization + membership +
        audit events in one transaction (identity contract/storage contract).

        ``audit_events`` is **required** keyword-only: provisioning events are
        part of the atomic unit (audit contract) and no default may let a caller
        silently skip them. The returned :class:`ProvisionedUser` echoes the
        caller-supplied objects unchanged — nothing is minted or re-read.

        Duplicate/concurrency semantics: the identity tuple is the **sole**
        race/convergence key (application-role). A UNIQUE violation on it is
        interpreted as identity contract's concurrent first-login race (both attempts
        carry the same identity tuple) and raises
        :class:`DuplicateExternalIdentityError` after a full rollback, with
        ``existing_user_id`` resolved by the adapter when it can and ``None``
        otherwise. Email is never a conflict here: a batch that shares an
        address with an existing user but carries a fresh identity tuple
        provisions a second, independent user. Other UNIQUE violations
        (organization slug, membership pair) propagate as their own
        :class:`DuplicateEntityError` kind. Every failure path is
        fully rolled back: no partial user, organization, membership, or
        audit rows survive a rejected batch.

        Raises:
            DuplicateExternalIdentityError: identity-tuple collision,
                including the concurrent-provisioning race.
            DuplicateEntityError: ``kind="organization_slug"`` /
                ``kind="membership"`` / ``kind="entity_id"`` for the remaining
                conflicts.
            ReferenceNotFoundError: when a cross-check reveals a parent the
                batch does not itself create.
        """
        ...

    def get_organization_onboarding_request(
        self, organization_id: OrganizationId
    ) -> OrganizationOnboardingRequest | None:
        """Read the durable onboarding outbox record for an organization."""
        ...

    def update_organization_onboarding_request(
        self, request: OrganizationOnboardingRequest
    ) -> None:
        """Persist a dispatcher attempt/result without storing credentials."""
        ...

    def provision_organization(
        self,
        *,
        organization: Organization,
        membership: Membership,
        audit_events: Sequence[AuditEvent],
    ) -> ProvisionedOrganization:
        """Atomically write organization + membership + audit events in one
        transaction (organization design notes design choice 2; a storage contract compound —
        the storage contract addition is an escalated contract-revision proposal).

        Organization creation must not be two sequential writes: the owner
        membership has no repair path (no organization update/delete exists),
        so a crash between ``create_organization`` and ``create_membership``
        would burn the slug forever behind a permanent 409. This compound is
        the sanctioned atomic unit: one transaction over the same row-insert
        behavior the standalone paths use; every failure path is fully rolled back,
        so no partial organization, membership, or audit rows survive a
        rejected batch.

        ``audit_events`` is **required** keyword-only (same discipline as
        :meth:`provision_user`): creation events are part of the atomic unit
        (audit contract) and no default may let a caller silently skip them. The
        returned :class:`ProvisionedOrganization` echoes the caller-supplied
        objects unchanged — storage mints nothing and does not re-read.

        Conflict semantics differ from :meth:`provision_user` **on purpose**:
        there is no race-convergence here. A taken slug is a plain
        :class:`DuplicateEntityError` (``kind="organization_slug"``) — a
        conflict, never a converge; taken ``org_``/``mem_``/``aud_`` record
        ids surface as ``kind="entity_id"``. The membership's ``user_id`` is
        the only parent the batch does not itself create: unknown, it raises
        :class:`ReferenceNotFoundError` (the organization and audit FKs are
        satisfied inside the batch).

        **DynamoDB replication obligation:** DynamoDB must enforce the same
        all-or-nothing batch, the same conflict kinds, and the same reference
        checks inside its conditional writes; the conformance suite pins the
        observable behavior, not the mechanism.

        Raises:
            DuplicateEntityError: ``kind="organization_slug"`` for a taken
                slug, ``kind="entity_id"`` for a taken record id.
            ReferenceNotFoundError: when ``membership.user_id`` is unknown.
        """
        ...

    # -- Login state and application sessions (Phase 11) ----------------------
    #
    # Additive Phase 11 surface backing the authorization-code session flow.
    # These records are caller-formed end to end: storage mints no id and no
    # ``expires_at`` (the same discipline as every ``create_*`` above). Their
    # *reads* evaluate expiry against the adapter's own clock — a read is not
    # a write, so the "never mints timestamps" rule does not forbid it. An
    # expired record behaves as absent (``None``); it is not a
    # :class:`EntityNotFoundError`, because these are lookups, not the §12
    # resolve signal.

    def save_oauth_login_state(self, state: OAuthLoginState) -> None:
        """Persist a pending OAuth login state (single-use PKCE verifier).

        Returns ``None`` — storage mints nothing and re-reads nothing. The
        ``state_id`` is the caller-minted lookup key.

        Raises:
            DuplicateEntityError: ``kind="entity_id"`` when ``state.state_id``
                was already saved (a minted state id must be unique).
        """
        ...

    def consume_oauth_login_state(self, state_id: str) -> OAuthLoginState | None:
        """Atomically fetch-and-delete one login state (replay-safe).

        Get-and-delete in a single atomic step: exactly one concurrent caller
        receives the record; every other caller (a replay, or a second tab
        racing the first) gets ``None``. A state read at/past ``expires_at``
        also yields ``None`` (treated as absent and, on adapters that can,
        removed). Never raises for an unknown/expired/replayed id — the
        callback maps ``None`` to a 401, so the storage contract must not
        surface :class:`EntityNotFoundError` here.
        """
        ...

    def create_app_session(self, session: AppSession) -> AppSession:
        """Persist a new application session (caller-echo).

        Storage mints nothing: the stored record is exactly ``session``. The
        ``session_id`` is the caller-minted opaque cookie key.

        Raises:
            DuplicateEntityError: ``kind="entity_id"`` when ``session.session_id``
                was already created.
        """
        ...

    def get_app_session(self, session_id: str) -> AppSession | None:
        """Load a live application session by its opaque id.

        Returns the stored :class:`AppSession` when the id exists and is
        strictly before ``expires_at``; returns ``None`` for an unknown id and
        for a session at/past ``expires_at`` (expired sessions are
        indistinguishable from absent ones to the caller). Never raises
        :class:`EntityNotFoundError` — session verification treats ``None`` as
        "not logged in".
        """
        ...

    def save_service_authorization_code(self, code: ServiceAuthorizationCode) -> None:
        """Persist a caller-formed, digest-only service authorization code.

        A duplicate digest raises ``DuplicateEntityError(kind="entity_id")``.
        No plaintext code is accepted by this storage contract.
        """
        ...

    def consume_service_authorization_code(
        self, code_digest: str
    ) -> ServiceAuthorizationCode | None:
        """Atomically mark one unexpired, unconsumed code consumed.

        At most one concurrent caller receives the context. Unknown,
        expired, consumed, and replayed digests all return ``None``.
        """
        ...


__all__ = [
    "DuplicateEntityError",
    "DuplicateEntityKind",
    "DuplicateExternalIdentityError",
    "EntityNotFoundError",
    "InvalidCursorError",
    "LastActiveAdministratorError",
    "ProvisionedOrganization",
    "ProvisionedUser",
    "ReferenceNotFoundError",
    "RoleTransition",
    "RoleTransitionOutcome",
    "Storage",
    "StorageError",
]
