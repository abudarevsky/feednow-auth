"""Domain-oriented storage contract (Phase 02, spec §11/§12).

This module is the *only* storage surface application code (Phases 03, 05, 06)
may depend on. It declares the 19 §11/§12 operations as a
:class:`typing.Protocol` plus the domain error vocabulary adapters raise.

Contract-wide rules (pinned by the Phase 02 breakdown; adapters must not
reinterpret them):

- **Synchronous protocol.** Spec §11's example and both target adapters
  (stdlib ``sqlite3``, ``boto3``) are synchronous, and FastAPI runs sync calls
  through its threadpool. ``Storage`` methods are plain ``def``; async would be
  an invented constraint.
- **Domain types only.** Every signature uses :mod:`app.models` types plus the
  :class:`ProvisionedUser`/:class:`ProvisionedOrganization` result bundles
  below. No SQL/SQLite/DynamoDB-specific
  value may cross this boundary: no rows, no ``LastEvaluatedKey``, no
  ``ConditionalCheckFailedException``, no sessions, no pagination tokens with
  interpretable content, and no driver exceptions (spec §11 leak examples;
  acceptance criterion 1). Adapters translate driver errors into the classes
  below; HTTP mapping (404/409) is Phase 04+ work in ``app/api``, untouched by
  this phase.
- **Storage never mints IDs or timestamps.** Every write receives a fully
  formed domain entity: ``usr_``/``org_``/``key_``/``extid_``/``mem_``/``aud_``
  ids and ``created_at``/``updated_at`` are caller-populated (generation
  strategies are Phase 03/05 work; a storage-side generator would become the
  de facto entropy contract). ``revoke_api_key`` likewise takes ``revoked_at``
  from the caller (:func:`app.models.timestamps.utc_now` is the clock source).
- **Referential integrity.** Child rows with unknown parents
  (identity→user; membership→organization+user; api_key→organization+creator;
  audit→organization) raise :class:`ReferenceNotFoundError`. DynamoDB has no
  foreign keys, so this docstring is the obligation for Phase 06 to replicate
  the checks inside its conditional writes; conformance pins the observable
  behavior, not the mechanism.
- **Primary-key collisions are domain conflicts.** A ``create_*``/``append_*``
  call may receive an already-persisted record id; that violation surfaces as
  :class:`DuplicateEntityError` with ``kind="entity_id"``, **never** a raw
  driver error. The five domain-uniqueness kinds below do not express it.
- **Tenant normalization.** ``provider_tenant=None`` participates in the
  external-identity uniqueness tuple as a normalized empty string and reads
  back as ``None``; the mapping is lossless because
  :data:`~app.models.external_identity.ProviderTenant` pins ``min_length=1``.
  Adapters must apply it so NULL cannot smuggle duplicate identities past a
  ``UNIQUE`` index (SQLite treats NULLs as distinct).
- **Corrupt stored values fail loudly.** Row→domain reconstruction goes
  through ``model_validate``, so a bad enum string or ID prefix raises rather
  than being silently coerced (documented tripwire).
- **No read/list surface for audit events this phase.** Audit is append-only
  by contract; listing/querying is deferred to Phase 08.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict

from app.models.api_key import ApiKey, KeyId
from app.models.audit_event import AuditEvent
from app.models.enums import IdentityProvider
from app.models.external_identity import ExternalIdentity, ProviderTenant
from app.models.ids import ApiKeyId, OrganizationId, ProviderSubject, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.pagination import Page, PageParams
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
    *not* a ``None`` return; raising is Phase 03's "needs provisioning" signal.
    Whether HTTP answers 404 or 204 is Phase 04+ mapping work.
    """


class DuplicateEntityKind(StrEnum):
    """Stable discriminator for :class:`DuplicateEntityError` (spec §4/§8).

    Additive vocabulary: renaming or removing a value is a contract change
    requiring a spec revision. ``entity_id`` covers PRIMARY KEY (``id``)
    collisions on any stored record; the remaining values name the five
    domain-uniqueness constraints (external-identity tuple, membership pair,
    organization slug, user email, ``api_keys.key_id`` credential segment).
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

    In spec §6's concurrent-first-login race both attempts carry the *same*
    email **and** the same identity tuple, so the loser's first UNIQUE
    violation may be ``users.email`` rather than the identity index. Inside
    ``provision_user`` any UNIQUE violation on the email or the identity tuple
    is interpreted as that race and surfaces as this error (kind is pinned to
    ``external_identity``), never as a plain email conflict.

    ``existing_user_id`` is the winner's ``usr_`` identity when the adapter can
    resolve it after rolling back, else ``None`` — so Phase 03 converges
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


# ---------------------------------------------------------------------------
# Compound-operation results
# ---------------------------------------------------------------------------


class ProvisionedUser(BaseModel):
    """Frozen result bundle returned by :meth:`Storage.provision_user`.

    **Caller-echo contract:** the bundle carries the caller-supplied domain
    objects *unchanged*. Storage mints nothing and does not re-read what it
    wrote — there is no read-back, no id/timestamp regeneration, and no
    adapter row leakage. Persistence is proven by the conformance suite's read
    cases and, for audit rows, by the duplicate-append proof; Phase 06 must
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
    duplicate-append proof; Phase 06 must not add reads to honor this shape.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    organization: Organization
    membership: Membership
    audit_events: tuple[AuditEvent, ...]


# ---------------------------------------------------------------------------
# The protocol (19 methods: spec §11 surface + the §12 compound
# ``provision_user`` + the Phase 04 compound ``provision_organization``)
# ---------------------------------------------------------------------------


@runtime_checkable
class Storage(Protocol):
    """Domain-oriented storage operations (spec §11/§12).

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

        Raises:
            DuplicateEntityError: ``kind="user_email"`` when the email is
                taken (email is a constraint, never an identity), or
                ``kind="entity_id"`` when ``user.id`` already exists.
        """
        ...

    def get_user(self, user_id: UserId) -> User:
        """Load a user by ``usr_`` application identity.

        Raises:
            EntityNotFoundError: when no such user exists.
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

        **This method *is* spec §12's ``resolve_external_identity``** — one
        operation, §11's name; there is no *separate* ``resolve_external_identity`` method
        on this protocol (the naming mismatch is a spec-revision proposal).

        ``provider_subject`` is a provider-side string (Cognito ``sub``,
        Shopify shop ID) and is never coerced into, or matched against, a
        ``usr_`` application identity. A miss raises and never returns ``None``
        — that exception is Phase 03's "needs provisioning" signal.

        Raises:
            EntityNotFoundError: when no identity matches the tuple.
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

    def list_user_organizations(
        self,
        user_id: UserId,
        page: PageParams,
    ) -> Page[Organization]:
        """Page through organizations the user belongs to.

        Domain operation, not a join helper: returns only organizations where
        the user holds an **active** membership — ``disabled`` is a suspension
        and hides the organization (Phase 04 re-checks roles). Results are
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

        Removal is a physical delete (Phase 01 pinned ``disabled`` as
        suspension, not removal). Idempotency is *not* provided: a second
        delete of the same pair raises.

        Raises:
            EntityNotFoundError: when no such membership exists.
        """
        ...

    # -- API keys -----------------------------------------------------------

    def create_api_key(self, api_key: ApiKey) -> ApiKey:
        """Persist a new API-key credential row.

        The non-secret §8 ``key_id`` credential segment is unique. ``scopes``
        round-trip exactly (order and duplicates preserved — normalization is
        Phase 05 domain work). No plaintext secret exists on the model and none
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

        Tenancy is deliberately **not** filtered here: the §8 verification path
        must resolve the organization *from* the key, so the full row is
        returned regardless of organization and enforcing the §14 org-scoped
        route contract is the Phase 05 service's check of
        ``api_key.organization_id``, not a storage filter.

        ``api_key_id`` is the :class:`~app.models.ids.ApiKeyId` application
        identity — not the §8 credential segment (see
        :meth:`get_api_key_by_key_id`; the collision is also flagged in
        :mod:`app.api.schemas.manifest`).

        Raises:
            EntityNotFoundError: when no such key exists.
        """
        ...

    def get_api_key_by_key_id(self, key_id: KeyId) -> ApiKey:
        """Load a key by the §8 non-secret ``<key-id>`` credential segment.

        Point lookup on the unique segment inside ``fn_live_<key-id>_<secret>``
        — keyed by :data:`~app.models.api_key.KeyId`, a different type from the
        ``key_`` :class:`~app.models.ids.ApiKeyId` used by
        :meth:`get_api_key`. Returns stored truth: after revocation the row
        still resolves with ``status=revoked`` and ``revoked_at`` set, because
        status is data and rejection is Phase 05 verification work.

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
        is nothing to return. Phase 03-05 services use this for events outside
        any compound operation (``membership.removed``, ``api_key.revoked``,
        ...); only provisioning batches go through :meth:`provision_user`.
        ``metadata`` round-trips exactly as JSON. There is no audit read or
        list surface in this phase.

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
    ) -> ProvisionedUser:
        """Atomically provision user + identity + organization + membership +
        audit events in one transaction (spec §6/§12).

        ``audit_events`` is **required** keyword-only: provisioning events are
        part of the atomic unit (spec §16) and no default may let a caller
        silently skip them. The returned :class:`ProvisionedUser` echoes the
        caller-supplied objects unchanged — nothing is minted or re-read.

        Duplicate/concurrency semantics: any UNIQUE violation on the user
        email **or** the identity tuple is interpreted as spec §6's concurrent
        first-login race (both attempts carry the same email and identity
        tuple) and raises :class:`DuplicateExternalIdentityError` after a full
        rollback, with ``existing_user_id`` resolved by the adapter when it can
        and ``None`` otherwise. Other UNIQUE violations (organization slug,
        membership pair) propagate as their own :class:`DuplicateEntityError`
        kind. Every failure path is fully rolled back: no partial user,
        organization, membership, or audit rows survive a rejected batch.

        Raises:
            DuplicateExternalIdentityError: email/identity-tuple collision,
                including the concurrent-provisioning race.
            DuplicateEntityError: ``kind="organization_slug"`` /
                ``kind="membership"`` / ``kind="entity_id"`` for the remaining
                conflicts.
            ReferenceNotFoundError: when a cross-check reveals a parent the
                batch does not itself create.
        """
        ...

    def provision_organization(
        self,
        *,
        organization: Organization,
        membership: Membership,
        audit_events: Sequence[AuditEvent],
    ) -> ProvisionedOrganization:
        """Atomically write organization + membership + audit events in one
        transaction (Phase 04 breakdown decision 2; a spec §12 compound —
        the §12 addition is an escalated spec-revision proposal).

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
        (spec §16) and no default may let a caller silently skip them. The
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

        **Phase 06 replication obligation:** DynamoDB must enforce the same
        all-or-nothing batch, the same conflict kinds, and the same reference
        checks inside its conditional writes; the conformance suite pins the
        observable behavior, not the mechanism.

        Raises:
            DuplicateEntityError: ``kind="organization_slug"`` for a taken
                slug, ``kind="entity_id"`` for a taken record id.
            ReferenceNotFoundError: when ``membership.user_id`` is unknown.
        """
        ...


__all__ = [
    "DuplicateEntityError",
    "DuplicateEntityKind",
    "DuplicateExternalIdentityError",
    "EntityNotFoundError",
    "InvalidCursorError",
    "ProvisionedOrganization",
    "ProvisionedUser",
    "ReferenceNotFoundError",
    "Storage",
    "StorageError",
]
