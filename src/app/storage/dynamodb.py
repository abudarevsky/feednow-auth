"""DynamoDB adapter: schema, codecs, error translation, and contract operations.

Phase 06 task 2 laid down everything DynamoDB-specific that the contract
operations build on; **task 3** implemented the users/external-identity
operations (:meth:`DynamoDbStorage.create_user`, :meth:`DynamoDbStorage.get_user`,
:meth:`DynamoDbStorage.create_external_identity`,
:meth:`DynamoDbStorage.get_user_by_external_identity`) and **task 4** adds the
organizations/memberships group (:meth:`DynamoDbStorage.create_organization`,
:meth:`DynamoDbStorage.get_organization`, :meth:`DynamoDbStorage.create_membership`,
:meth:`DynamoDbStorage.get_membership`, :meth:`DynamoDbStorage.delete_membership`,
:meth:`DynamoDbStorage.list_user_organizations`,
:meth:`DynamoDbStorage.list_memberships`) and **task 5** adds the API-keys group
(:meth:`DynamoDbStorage.create_api_key`, :meth:`DynamoDbStorage.get_api_key`,
:meth:`DynamoDbStorage.get_api_key_by_key_id`, :meth:`DynamoDbStorage.list_api_keys`,
:meth:`DynamoDbStorage.revoke_api_key` — the first-write-wins CAS of decision 4),
and **task 6** adds audit append (:meth:`DynamoDbStorage.append_audit_event`) plus
the :meth:`DynamoDbStorage.provision_user` compound — one ``TransactWriteItems``
in SQLite's statement order with the §6 race converge of decision 3 — and
**task 7** adds the :meth:`DynamoDbStorage.provision_organization` compound
(the same transactional discipline with **no** race converge: a taken slug is a
plain conflict).
The module is importable on its own; nothing in ``app.main``/api/auth/services
reaches it (the subprocess ``import app.main`` boto3-free proof stays green
because only an explicit ``from app.storage.dynamodb import
open_dynamodb_storage`` loads this module).

Design carried from the Phase 06 breakdown (planner decisions 2, 3, 5, 6, 7):

- **Multi-table schema, single source.** :data:`SCHEMA` is the one authoritative
  table/key/GSI definition; the DynamoDB Local harness and (later) the Phase 07
  CDK stack consume it verbatim so the schema text exists exactly once.
- **Sortable timestamps.** :func:`encode_timestamp` re-implements the SQLite
  text convention (``sqlite.py`` is a completed Phase 02 contract surface and a
  byte-stable refactor for a 6-line codec is unjustified churn) — a
  cross-reference comment pins the shared format. Fixed-width microseconds make
  lexicographic order equal chronological order, which the GSI sort keys and
  keyset cursors rely on.
- **Tenant normalization.** ``provider_tenant=None`` participates in the
  identity-tuple constraint key as the normalized empty string and reads back
  as ``None`` (lossless: ``ProviderTenant`` pins ``min_length=1``).
- **Constraint / resume keys.** ``unique_constraints`` PK is
  ``<kind>#<normalized value>``; GSI sort keys put the ``#``-separated id
  tiebreaker last so ``(created_at, id)`` ordering is exact.
- **Opaque keyset cursors.** base64url JSON ``{"scope", "resume"}`` carrying
  the *last returned* item's index key attributes; a foreign-scope or malformed
  payload raises :class:`~app.storage.contract.InvalidCursorError` with fixed,
  echo-free messages, never a raw ``ValueError``/``binascii.Error``/driver error.
- **List reads are GSI scans with keyset cursors.** ``list_user_organizations``
  reassembles its page through one ``BatchGetItem`` read-back of the *trimmed*
  page's organization ids (decision 2's batch-boundary rule: the probe row's
  payload is never fetched), so the membership index supplies ordering and the
  organizations table supplies truth.
- **Positional conflict classification.** :func:`classify_cancellation_reasons`
  is a pure function over parsed ``CancellationReasons`` dicts plus the
  operation's same-ordered descriptor list; the first ``ConditionalCheckFailed``
  in submission order decides the domain error. Transient
  ``TransactionConflict`` becomes a retry verdict (:data:`RETRY`), throughput
  faults and unknown codes become the base :class:`~app.storage.contract.StorageError`,
  and no driver message, table name, region, or request id ever propagates.
- **Every multi-item write is one ``TransactWriteItems``** (decision 3), with a
  parallel, same-ordered descriptor list: base puts first, then constraint puts,
  then the parent ``ConditionCheck``s that replicate SQLite's foreign keys. A
  rejected batch leaves no residue (DynamoDB transactions are atomic), which is
  how the adapter reproduces SQLite's rollback-on-conflict behavior.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Final

import boto3
from botocore.exceptions import ClientError

from app.models.api_key import ApiKey, KeyId
from app.models.audit_event import AuditEvent
from app.models.enums import ApiKeyStatus, IdentityProvider, MembershipStatus
from app.models.external_identity import ExternalIdentity, ProviderTenant
from app.models.ids import ApiKeyId, OrganizationId, ProviderSubject, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.pagination import Page, PageParams, clamp_limit
from app.models.timestamps import UtcDatetime, ensure_utc
from app.models.user import User
from app.storage.contract import (
    DuplicateEntityError,
    DuplicateEntityKind,
    DuplicateExternalIdentityError,
    EntityNotFoundError,
    InvalidCursorError,
    ProvisionedOrganization,
    ProvisionedUser,
    ReferenceNotFoundError,
    StorageError,
)

# ---------------------------------------------------------------------------
# Schema (decision 2): the single source of table names, key schemas, and GSI
# definitions. The DynamoDB Local harness imports this and builds Create/Table
# payloads from it; Phase 07's CDK stack declares the same schema.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IndexSpec:
    """One global secondary index: name plus its key attribute names."""

    name: str
    partition_key: str
    sort_key: str


@dataclass(frozen=True)
class TableSpec:
    """One table's name suffix and key schema (decision 2's layout)."""

    name: str
    partition_key: str
    sort_key: str | None = None
    indexes: tuple[IndexSpec, ...] = ()

    def create_parameters(self, prefix: str) -> dict[str, Any]:
        """Build the ``CreateTable`` payload for this table under ``prefix``.

        Every key attribute (base and GSI) is a string; projections are ``ALL``
        so a Query over an index is self-contained for payloads that live on the
        indexed table. ``PAY_PER_REQUEST`` billing needs no throughput
        provisioning on Local; Phase 07's CDK declares capacity explicitly.
        """
        key_names = [self.partition_key]
        if self.sort_key is not None:
            key_names.append(self.sort_key)
        for index in self.indexes:
            key_names.extend((index.partition_key, index.sort_key))
        payload: dict[str, Any] = {
            "TableName": f"{prefix}{self.name}",
            "AttributeDefinitions": [
                {"AttributeName": name, "AttributeType": "S"} for name in dict.fromkeys(key_names)
            ],
            "KeySchema": [
                {"AttributeName": self.partition_key, "KeyType": "HASH"},
                *(
                    [{"AttributeName": self.sort_key, "KeyType": "RANGE"}]
                    if self.sort_key is not None
                    else []
                ),
            ],
            "BillingMode": "PAY_PER_REQUEST",
        }
        if self.indexes:
            payload["GlobalSecondaryIndexes"] = [
                {
                    "IndexName": index.name,
                    "KeySchema": [
                        {"AttributeName": index.partition_key, "KeyType": "HASH"},
                        {"AttributeName": index.sort_key, "KeyType": "RANGE"},
                    ],
                    "Projection": {"ProjectionType": "ALL"},
                }
                for index in self.indexes
            ]
        return payload


#: The seven-table schema (decision 2): record-id-keyed entity tables, the
#: memberships table keyed by the native (org, user) pair with both listing
#: GSIs, the api-keys listing GSI, and the key-only ``unique_constraints``
#: table that enforces every uniqueness DynamoDB cannot enforce natively.
SCHEMA: Final[tuple[TableSpec, ...]] = (
    TableSpec(name="users", partition_key="pk"),
    TableSpec(name="organizations", partition_key="pk"),
    TableSpec(name="external_identities", partition_key="pk"),
    TableSpec(name="audit_events", partition_key="pk"),
    TableSpec(
        name="api_keys",
        partition_key="pk",
        indexes=(IndexSpec(name="by-organization", partition_key="g_org", sort_key="g_created"),),
    ),
    TableSpec(
        name="memberships",
        partition_key="organization_id",
        sort_key="user_id",
        indexes=(
            IndexSpec(name="by-organization", partition_key="g_org", sort_key="g_created"),
            IndexSpec(name="by-user", partition_key="g_user", sort_key="g_org_created"),
        ),
    ),
    TableSpec(name="unique_constraints", partition_key="pk"),
)

#: The :data:`SCHEMA` table names as a set — the adapter's own guard that an
#: operation never asks for a table the schema does not declare.
_SCHEMA_TABLE_NAMES: Final[frozenset[str]] = frozenset(spec.name for spec in SCHEMA)

# ---------------------------------------------------------------------------
# Constraint kinds (decision 2): the ``unique_constraints`` PK label and the
# frozen ``DuplicateEntityKind`` each enforced item maps to. ``membership_id``
# is the ``mem_`` record-id guard (kind ``entity_id``); the ``membership`` pair
# kind belongs to the org/user tuple, which is native on the base table and so
# never appears as a constraint item.
# ---------------------------------------------------------------------------


class ConstraintKind(StrEnum):
    """``unique_constraints`` PK label for one enforced uniqueness."""

    USER_EMAIL = "user_email"
    ORGANIZATION_SLUG = "organization_slug"
    EXTERNAL_IDENTITY = "external_identity"
    API_KEY_ID = "api_key_id"
    MEMBERSHIP_ID = "membership_id"


#: Constraint-item label -> the domain conflict kind it surfaces as.
DUPLICATE_KIND_BY_CONSTRAINT: Final[Mapping[ConstraintKind, DuplicateEntityKind]] = {
    ConstraintKind.USER_EMAIL: DuplicateEntityKind.USER_EMAIL,
    ConstraintKind.ORGANIZATION_SLUG: DuplicateEntityKind.ORGANIZATION_SLUG,
    ConstraintKind.EXTERNAL_IDENTITY: DuplicateEntityKind.EXTERNAL_IDENTITY,
    ConstraintKind.API_KEY_ID: DuplicateEntityKind.API_KEY_ID,
    ConstraintKind.MEMBERSHIP_ID: DuplicateEntityKind.ENTITY_ID,
}

# ---------------------------------------------------------------------------
# List-scope tags embedded in keyset cursors (contract: a cursor from one list
# is invalid for another). Adapter-internal; never interpreted above the adapter.
# ---------------------------------------------------------------------------

CURSOR_SCOPE_USER_ORGANIZATIONS: Final = "user_organizations"
CURSOR_SCOPE_MEMBERSHIPS: Final = "memberships"
CURSOR_SCOPE_API_KEYS: Final = "api_keys"

#: The complete key-attribute sets the membership-index cursors resume from.
#: A GSI ``ExclusiveStartKey`` needs **both** the index keys and the base
#: table keys, so each resume payload carries the last returned item's four
#: key attributes (decision 5). Adapter-internal; never parsed above here.
_USER_ORGANIZATIONS_RESUME_KEYS: Final[tuple[str, ...]] = (
    "organization_id",
    "user_id",
    "g_user",
    "g_org_created",
)
_MEMBERSHIPS_RESUME_KEYS: Final[tuple[str, ...]] = (
    "organization_id",
    "user_id",
    "g_org",
    "g_created",
)
#: The api-keys index cursors resume from the last returned key's base ``pk``
#: plus its two GSI key attributes (the same both-key-sets rule as above).
_API_KEYS_RESUME_KEYS: Final[tuple[str, ...]] = ("pk", "g_org", "g_created")

#: Items evaluated per ``Query`` call (decision 5): a scan batch, *not* the
#: page size — the effective page limit may be smaller or larger and the loop
#: simply keeps fetching until the page's ``limit + 1`` accumulation or the
#: segment is exhausted.
SCAN_BATCH: Final = 100

#: Bounded re-requests of ``BatchGetItem`` unprocessed keys (production can
#: partialize; Local answers completely). Exhaustion is a retryable
#: :class:`~app.storage.contract.StorageError`.
_BATCH_READ_MAX_ATTEMPTS: Final = 5

# ---------------------------------------------------------------------------
# Codecs (decision 6; pure helpers, unit-tested in tests/unit/test_dynamodb_codec.py)
# ---------------------------------------------------------------------------


def encode_timestamp(value: datetime) -> str:
    """Encode an aware datetime as the fixed-width sortable UTC TEXT form.

    ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` — microseconds are always present so
    lexicographic order equals chronological order (a zero-microsecond value
    must still carry ``.000000`` or a mixed GSI sort-key range mis-sorts).
    Mirrors :func:`app.storage.sqlite.encode_timestamp` (``sqlite.py:236-244``);
    deliberately re-implemented here rather than shared (breakdown decision 6).
    Naive datetimes are rejected (:func:`~app.models.timestamps.ensure_utc`).
    """
    normalized = ensure_utc(value)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def decode_timestamp(text: str) -> datetime:
    """Decode a stored timestamp back to an aware UTC datetime.

    Raises ``ValueError`` for malformed or naive stored text — a corrupt item
    must fail loudly, not coerce (contract tripwire).
    """
    return ensure_utc(datetime.fromisoformat(text))


def encode_provider_tenant(value: ProviderTenant | None) -> str:
    """Normalize an optional tenant for storage: ``None`` becomes ``''``.

    ``''`` can never be a legitimate domain value (``ProviderTenant`` pins
    ``min_length=1``), so the mapping is lossless and keeps the identity-tuple
    constraint key NULL-free — identical to the SQLite normalization.
    """
    return "" if value is None else value


def decode_provider_tenant(value: str) -> ProviderTenant | None:
    """Inverse of :func:`encode_provider_tenant` (``''`` reads back as ``None``)."""
    return value or None


def encode_constraint_key(kind: ConstraintKind, normalized_value: str) -> str:
    """Build a ``unique_constraints`` PK: ``<kind>#<normalized value>``.

    Key-only (decision 2): the whole uniqueness is carried by the partition key
    so a lookup whose entity id is *unknown* is a single ``GetItem``.
    """
    return f"{kind.value}#{normalized_value}"


def encode_external_identity_value(
    provider: IdentityProvider,
    provider_subject: str,
    provider_tenant: ProviderTenant | None,
) -> str:
    """Normalize the ``(provider, subject, tenant)`` tuple into one constraint value.

    The tenant goes through :func:`encode_provider_tenant` so ``None`` and ``''``
    collapse to the same key (``provider#subject#tenant``).
    """
    return f"{provider.value}#{provider_subject}#{encode_provider_tenant(provider_tenant)}"


def encode_sort_key(created_at: datetime, tiebreaker_id: str) -> str:
    """Build a GSI sort key: ``<sortable created_at>#<id>`` (decision 2).

    The fixed-width timestamp leads and the ``#``-separated id tiebreaker is
    last, so lexicographic order equals ``(created_at, id)`` chronological order
    and the tiebreaker is exact.
    """
    return f"{encode_timestamp(created_at)}#{tiebreaker_id}"


# ---------------------------------------------------------------------------
# Item mapping (decision 6): domain entity <-> stored item. Attribute names
# mirror the SQLite TEXT column names 1:1 so parity review is a line-by-line
# comparison; every reconstruction goes through ``model_validate``, so a corrupt
# stored value fails loudly instead of being coerced (contract tripwire).
# ---------------------------------------------------------------------------


def user_item(user: User) -> dict[str, Any]:
    """The ``users`` item for one domain user (``pk`` is the ``usr_`` identity)."""
    return {
        "pk": str(user.id),
        "display_name": user.display_name,
        "email": user.email,
        "status": str(user.status),
        "created_at": encode_timestamp(user.created_at),
        "updated_at": encode_timestamp(user.updated_at),
    }


def user_from_item(item: Mapping[str, Any]) -> User:
    """Rebuild a :class:`~app.models.user.User` from a ``users`` item."""
    return User.model_validate(
        {
            "id": item["pk"],
            "display_name": item["display_name"],
            "email": item["email"],
            "status": item["status"],
            "created_at": decode_timestamp(item["created_at"]),
            "updated_at": decode_timestamp(item["updated_at"]),
        }
    )


def external_identity_item(identity: ExternalIdentity) -> dict[str, Any]:
    """The ``external_identities`` item for one domain identity.

    The tenant goes through :func:`encode_provider_tenant` so ``None`` is stored
    as ``''`` exactly as SQLite stores it (a NULL would be a different tuple).
    """
    return {
        "pk": str(identity.id),
        "user_id": str(identity.user_id),
        "provider": str(identity.provider),
        "provider_subject": identity.provider_subject,
        "provider_tenant": encode_provider_tenant(identity.provider_tenant),
        "created_at": encode_timestamp(identity.created_at),
    }


def external_identity_from_item(item: Mapping[str, Any]) -> ExternalIdentity:
    """Rebuild an :class:`~app.models.external_identity.ExternalIdentity` from an item."""
    return ExternalIdentity.model_validate(
        {
            "id": item["pk"],
            "user_id": item["user_id"],
            "provider": item["provider"],
            "provider_subject": item["provider_subject"],
            "provider_tenant": decode_provider_tenant(item["provider_tenant"]),
            "created_at": decode_timestamp(item["created_at"]),
        }
    )


def organization_item(organization: Organization) -> dict[str, Any]:
    """The ``organizations`` item for one domain organization (``pk`` is ``org_``)."""
    return {
        "pk": str(organization.id),
        "name": organization.name,
        "slug": organization.slug,
        "type": str(organization.type),
        "status": str(organization.status),
        "created_at": encode_timestamp(organization.created_at),
        "updated_at": encode_timestamp(organization.updated_at),
    }


def organization_from_item(item: Mapping[str, Any]) -> Organization:
    """Rebuild an :class:`~app.models.organization.Organization` from an item."""
    return Organization.model_validate(
        {
            "id": item["pk"],
            "name": item["name"],
            "slug": item["slug"],
            "type": item["type"],
            "status": item["status"],
            "created_at": decode_timestamp(item["created_at"]),
            "updated_at": decode_timestamp(item["updated_at"]),
        }
    )


def membership_item(membership: Membership, organization_created_at: datetime) -> dict[str, Any]:
    """The ``memberships`` item for one domain membership (decision 2's layout).

    The base keys carry the native ``(organization_id, user_id)`` pair (pair
    uniqueness and the tuple lookups are native); the four GSI key attributes
    carry both listing access patterns. ``g_org_created`` denormalizes the
    **organization** ``created_at`` (the caller supplies it:
    ``create_membership`` reads the org, the provisioning compounds construct
    it) so ``list_user_organizations`` orders by organization creation time
    without a join — safe because no organization update path exists in the
    frozen contract, so ``created_at`` is immutable once written.
    """
    return {
        "organization_id": str(membership.organization_id),
        "user_id": str(membership.user_id),
        "id": str(membership.id),
        "role": str(membership.role),
        "status": str(membership.status),
        "created_at": encode_timestamp(membership.created_at),
        "g_org": str(membership.organization_id),
        "g_created": encode_sort_key(membership.created_at, str(membership.id)),
        "g_user": str(membership.user_id),
        "g_org_created": encode_sort_key(organization_created_at, str(membership.organization_id)),
    }


def membership_from_item(item: Mapping[str, Any]) -> Membership:
    """Rebuild a :class:`~app.models.membership.Membership` from an item.

    Only the base attributes are read back; the GSI key attributes are index
    plumbing and never part of the domain entity.
    """
    return Membership.model_validate(
        {
            "id": item["id"],
            "organization_id": item["organization_id"],
            "user_id": item["user_id"],
            "role": item["role"],
            "status": item["status"],
            "created_at": decode_timestamp(item["created_at"]),
        }
    )


def api_key_item(api_key: ApiKey) -> dict[str, Any]:
    """The ``api_keys`` item for one domain key (decision 2's layout).

    ``pk`` is the ``key_`` application identity; the two GSI key attributes
    carry the organization-scoped listing (SK = ``created_at`` + ``#`` + ``key_``
    id, so ``(created_at, id)`` order is exact). ``scopes`` is stored as a
    native DynamoDB **L** (decision 6): list order and duplicates are preserved
    by the type itself — no JSON-text emulation of SQLite's codec. Optional
    timestamps are *absent attributes* when ``None`` (DynamoDB has no NULL
    convention here), which the reader maps back symmetrically. No plaintext
    secret exists on the model and none is derived or logged here.
    """
    item: dict[str, Any] = {
        "pk": str(api_key.id),
        "organization_id": str(api_key.organization_id),
        "created_by_user_id": str(api_key.created_by_user_id),
        "name": api_key.name,
        "key_id": api_key.key_id,
        "key_prefix": api_key.key_prefix,
        "secret_hash": api_key.secret_hash,
        "environment": str(api_key.environment),
        "scopes": list(api_key.scopes),
        "status": str(api_key.status),
        "created_at": encode_timestamp(api_key.created_at),
        "g_org": str(api_key.organization_id),
        "g_created": encode_sort_key(api_key.created_at, str(api_key.id)),
    }
    for attribute, value in (
        ("last_used_at", api_key.last_used_at),
        ("expires_at", api_key.expires_at),
        ("revoked_at", api_key.revoked_at),
    ):
        if value is not None:
            item[attribute] = encode_timestamp(value)
    return item


def api_key_from_item(item: Mapping[str, Any]) -> ApiKey:
    """Rebuild an :class:`~app.models.api_key.ApiKey` from an item.

    Reconstruction goes through ``model_validate`` (decision 6): a corrupt
    stored value fails loudly instead of being coerced. The GSI key attributes
    are index plumbing and never part of the domain entity.
    """
    payload: dict[str, Any] = {
        "id": item["pk"],
        "organization_id": item["organization_id"],
        "created_by_user_id": item["created_by_user_id"],
        "name": item["name"],
        "key_id": item["key_id"],
        "key_prefix": item["key_prefix"],
        "secret_hash": item["secret_hash"],
        "environment": item["environment"],
        "scopes": list(item["scopes"]),
        "status": item["status"],
        "created_at": decode_timestamp(item["created_at"]),
    }
    for attribute in ("last_used_at", "expires_at", "revoked_at"):
        stored = item.get(attribute)
        payload[attribute] = None if stored is None else decode_timestamp(stored)
    return ApiKey.model_validate(payload)


def audit_event_item(audit_event: AuditEvent) -> dict[str, Any]:
    """The ``audit_events`` item for one domain audit event (``pk`` is ``aud_``).

    ``metadata`` is stored as a native DynamoDB **M** (decision 6): JSON-safe
    values map onto S/N/BOOL/NULL/L/M directly and the contract's "round-trips
    exactly" is observable equality, which native types satisfy — JSON-text
    emulation of SQLite's codec would add lossy number handling for no
    behavioral gain. Optional ``target_type``/``target_id`` are *absent
    attributes* when ``None`` (the same convention as the api-key optional
    timestamps). There is deliberately no ``audit_event_from_item`` reader:
    the contract has no audit read surface this phase (Phase 08 owns the query
    path and adds the codec with it); append is write-only by contract.
    """
    item: dict[str, Any] = {
        "pk": str(audit_event.id),
        "organization_id": str(audit_event.organization_id),
        "actor_type": audit_event.actor_type,
        "actor_id": str(audit_event.actor_id),
        "action": audit_event.action,
        "metadata": dict(audit_event.metadata),
        "created_at": encode_timestamp(audit_event.created_at),
    }
    if audit_event.target_type is not None:
        item["target_type"] = audit_event.target_type
    if audit_event.target_id is not None:
        item["target_id"] = audit_event.target_id
    return item


# ---------------------------------------------------------------------------
# Constraint items (decision 2): the ``unique_constraints`` rows enforcing the
# uniquenesses DynamoDB cannot enforce on a base-table key. Key-only by design,
# so a lookup whose entity id is *unknown* is a single ``GetItem``. ``kind`` and
# ``entity_id`` are on every item; ``user_id`` additionally on the email and
# identity-tuple items, which is how ``get_user_by_external_identity`` and
# ``provision_user``'s race resolution read the owning user without a second
# query (the SQLite paths do the same through an index lookup / a JOIN).
# ---------------------------------------------------------------------------


def user_email_constraint_item(user: User) -> dict[str, Any]:
    """The ``user_email`` constraint item guarding one user's email."""
    return {
        "pk": encode_constraint_key(ConstraintKind.USER_EMAIL, user.email),
        "kind": ConstraintKind.USER_EMAIL.value,
        "entity_id": str(user.id),
        "user_id": str(user.id),
    }


def external_identity_constraint_item(identity: ExternalIdentity) -> dict[str, Any]:
    """The ``external_identity`` constraint item guarding one provider tuple."""
    return {
        "pk": encode_constraint_key(
            ConstraintKind.EXTERNAL_IDENTITY,
            encode_external_identity_value(
                identity.provider, identity.provider_subject, identity.provider_tenant
            ),
        ),
        "kind": ConstraintKind.EXTERNAL_IDENTITY.value,
        "entity_id": str(identity.id),
        "user_id": str(identity.user_id),
    }


def organization_slug_constraint_item(organization: Organization) -> dict[str, Any]:
    """The ``organization_slug`` constraint item guarding one slug."""
    return {
        "pk": encode_constraint_key(ConstraintKind.ORGANIZATION_SLUG, organization.slug),
        "kind": ConstraintKind.ORGANIZATION_SLUG.value,
        "entity_id": str(organization.id),
    }


def membership_id_constraint_item(membership: Membership) -> dict[str, Any]:
    """The ``membership_id`` guard item for one ``mem_`` record id.

    Decision 2: the membership record id is the only non-PK record id, so it
    gets a guard item mapping to ``kind="entity_id"``; the ``(organization,
    user)`` pair uniqueness is native on the base table and never appears as
    a constraint item.
    """
    return {
        "pk": encode_constraint_key(ConstraintKind.MEMBERSHIP_ID, str(membership.id)),
        "kind": ConstraintKind.MEMBERSHIP_ID.value,
        "entity_id": str(membership.id),
    }


def api_key_id_constraint_item(api_key: ApiKey) -> dict[str, Any]:
    """The ``api_key_id`` constraint item guarding one §8 credential segment.

    Decision 2: the segment is the §8 uniqueness DynamoDB cannot enforce on the
    ``key_``-keyed base table, so it gets a guard item mapped to
    ``kind="api_key_id"`` (the frozen ``DuplicateEntityKind``); the ``key_``
    record id is native on the base table and needs no guard. The item carries
    only ``kind``/``entity_id`` (no ``user_id``): ``get_api_key_by_key_id``
    resolves segment → ``key_`` id → payload through it.
    """
    return {
        "pk": encode_constraint_key(ConstraintKind.API_KEY_ID, api_key.key_id),
        "kind": ConstraintKind.API_KEY_ID.value,
        "entity_id": str(api_key.id),
    }


# ---------------------------------------------------------------------------
# Keyset cursors (decision 5): opaque, adapter-generated. The resume payload
# carries the *last returned* item's index key attributes (never the raw
# LastEvaluatedKey, which may sit past filtered rows and would skip items).
# ---------------------------------------------------------------------------


def encode_cursor(scope: str, resume: Mapping[str, str]) -> str:
    """Encode an opaque keyset cursor for one list scope.

    The result is unpadded base64url JSON ``{"scope": <tag>, "resume": {...}}``;
    callers treat it as an opaque string and never parse it (only this module
    decodes). DynamoDB cursors need not byte-match SQLite's — the conformance
    suite never compares cursor bytes across adapters.
    """
    payload = {"scope": scope, "resume": dict(resume)}
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(scope: str, cursor: str) -> dict[str, str]:
    """Decode a cursor, pin it to the expected list ``scope``, return the resume key.

    Any malformed, tampered, or foreign-scope token raises
    :class:`~app.storage.contract.InvalidCursorError` with a fixed, echo-free
    message — never a raw ``ValueError``, ``binascii.Error``, or driver error.
    """
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeError, binascii.Error) as exc:
        raise InvalidCursorError("cursor could not be decoded") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"scope", "resume"}
        or not isinstance(payload["scope"], str)
        or not isinstance(payload["resume"], dict)
    ):
        raise InvalidCursorError("cursor payload is malformed")
    if payload["scope"] != scope:
        raise InvalidCursorError("cursor was issued for a different list")
    resume: dict[str, str] = payload["resume"]
    if not resume or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in resume.items()
    ):
        raise InvalidCursorError("cursor payload is malformed")
    return resume


# ---------------------------------------------------------------------------
# Positional conflict classification (decision 3). Descriptors are the
# operation's same-ordered list describing what each submitted ``TransactItem``
# enforces; the classifier is a pure function over parsed reason dicts so it is
# unit-testable with synthetic payloads (no botocore objects beyond a
# ``ClientError`` factory).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DuplicateConflict:
    """Descriptor: a conditional put whose failure is a duplicate of ``kind``."""

    kind: DuplicateEntityKind

    def to_error(self) -> StorageError:
        return DuplicateEntityError(self.kind)


@dataclass(frozen=True)
class IdentityRaceConflict:
    """Descriptor: a ``provision_user`` email/identity-tuple failure.

    Spec §6's concurrent-first-login race is a converge, not a plain conflict;
    ``existing_user_id`` is resolved by the operation (task 6) after the
    rollback, so this carries the base error with ``None``.
    """

    def to_error(self) -> StorageError:
        return DuplicateExternalIdentityError()


@dataclass(frozen=True)
class ReferenceConflict:
    """Descriptor: a parent ``ConditionCheck`` whose failure is a missing parent."""

    def to_error(self) -> StorageError:
        return ReferenceNotFoundError("a referenced parent record does not exist")


#: One per submitted item, same order; decides the error when that item's
#: condition fails. ``membership`` base puts carry ``DuplicateConflict(
#: MEMBERSHIP)`` (the native org/user pair), every other base put
#: ``DuplicateConflict(ENTITY_ID)``.
type ConflictDescriptor = DuplicateConflict | IdentityRaceConflict | ReferenceConflict


class _RetrySentinel:
    """Marker: the cancellation was transient; re-run the whole write."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "RETRY"


#: Returned by the classifier for transient ``TransactionConflict``.
RETRY: Final = _RetrySentinel()

#: Bounded retries for a transiently cancelled transaction/conditional write
#: (the DynamoDB analogue of SQLite's ``busy_timeout`` blocking).
MAX_TRANSACTION_ATTEMPTS: Final = 5

_NO_ERROR_CODE: Final = "None"
_CONDITIONAL_CHECK_FAILED: Final = "ConditionalCheckFailed"
_TRANSACTION_CONFLICT: Final = "TransactionConflict"
_THROUGHPUT_CODES: Final = frozenset({"ThrottlingError", "ProvisionedThroughputExceeded"})
_TRANSIENT_SINGLE_ITEM_CODES: Final = frozenset(
    {"TransactionConflictException", "TransactionInProgressException"}
)
_THROUGHPUT_SINGLE_ITEM_CODES: Final = frozenset(
    {"ThrottlingException", "ProvisionedThroughputExceededException"}
)


def classify_cancellation_reasons(
    reasons: Sequence[Mapping[str, Any]],
    descriptors: Sequence[ConflictDescriptor],
) -> StorageError | _RetrySentinel:
    """Map an ordered ``CancellationReasons`` list to a domain error or retry.

    Pure over parsed reason dicts (entries are ``Code``/``Message`` only; the
    no-error code is the literal string ``"None"``). The **first
    ``ConditionalCheckFailed`` in submission order decides the error** via the
    positionally-aligned descriptor; only when no conditional check failed do
    transient codes yield :data:`RETRY` and throughput/unknown codes yield the
    base :class:`StorageError`. Driver ``Message`` text is never read, so no
    table name, region, or request id can leak.
    """
    for index, reason in enumerate(reasons):
        if reason.get("Code") == _CONDITIONAL_CHECK_FAILED:
            if index < len(descriptors):
                return descriptors[index].to_error()
            # A cancelled item with no descriptor is a programming error, not a
            # domain conflict: fail loudly with a fixed, leak-free message.
            return StorageError("storage transaction was cancelled")
    transient = False
    for reason in reasons:
        code = reason.get("Code")
        if code in (None, _NO_ERROR_CODE):
            continue
        if code == _TRANSACTION_CONFLICT:
            transient = True
        elif code in _THROUGHPUT_CODES:
            return StorageError("storage throughput was exceeded")
    if transient:
        return RETRY
    return StorageError("storage transaction failed")


def classify_client_error(
    exc: ClientError,
    descriptors: Sequence[ConflictDescriptor],
) -> StorageError | _RetrySentinel:
    """Translate a single ``ClientError`` (transaction or conditional write).

    A ``TransactionCanceledException`` is delegated to
    :func:`classify_cancellation_reasons` over its ``CancellationReasons``;
    single-item transient codes (:data:`RETRY`-worthy) and throughput faults
    are handled directly. A ``ConditionalCheckFailedException`` on a standalone
    conditional write is *expected* (the CAS-miss path) and is handled by the
    operation itself, so it never reaches this classifier; anything unrecognized
    becomes the base :class:`StorageError`.
    """
    code = str(exc.response.get("Error", {}).get("Code", ""))
    if code == "TransactionCanceledException":
        reasons = exc.response.get("CancellationReasons", [])
        return classify_cancellation_reasons(reasons, descriptors)
    if code in _TRANSIENT_SINGLE_ITEM_CODES:
        return RETRY
    if code in _THROUGHPUT_SINGLE_ITEM_CODES:
        return StorageError("storage throughput was exceeded")
    return StorageError("storage request failed")


def execute_transaction(
    submit: Callable[[], None],
    descriptors: Sequence[ConflictDescriptor],
    *,
    max_attempts: int = MAX_TRANSACTION_ATTEMPTS,
) -> None:
    """Run a ``TransactWriteItems`` submission with bounded transient retry.

    ``submit`` performs the raw write and raises ``ClientError`` on failure. A
    :data:`RETRY` verdict re-submits (a racing loser converges on the winner's
    committed rows); a domain error propagates immediately (no retry — a stable
    conflict will recur); exhausted retries become the base
    :class:`StorageError` (the retryable channel). Driver exceptions never
    escape: only :class:`~app.storage.contract.StorageError` subclasses do.
    """
    for _ in range(max_attempts):
        try:
            submit()
            return
        except ClientError as exc:
            verdict = classify_client_error(exc, descriptors)
            if isinstance(verdict, _RetrySentinel):
                continue
            raise verdict from None
    raise StorageError("storage transaction aborted by concurrent activity")


def execute_conditional_write(
    submit: Callable[[], None],
    *,
    max_attempts: int = MAX_TRANSACTION_ATTEMPTS,
) -> bool:
    """Run a standalone conditional write with bounded transient retry.

    Returns ``True`` when the write succeeded and ``False`` when the condition
    failed — the expected CAS-miss path, which the calling operation
    interprets (``delete_membership``: absence; ``revoke_api_key``: stored
    truth). Transient single-item conflict codes re-run the write (the
    :func:`execute_transaction` analogue for one-item writes); throughput
    faults and anything unrecognized become the base :class:`StorageError`.
    Driver exceptions never escape.
    """
    for _ in range(max_attempts):
        try:
            submit()
            return True
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code == "ConditionalCheckFailedException":
                return False
            if code in _TRANSIENT_SINGLE_ITEM_CODES:
                continue
            if code in _THROUGHPUT_SINGLE_ITEM_CODES:
                raise StorageError("storage throughput was exceeded") from None
            raise StorageError("storage request failed") from None
    raise StorageError("storage conditional write aborted by concurrent activity")


# ---------------------------------------------------------------------------
# Adapter shell + contract operations (decision 7). Users/external identities
# (task 3), organizations/memberships (task 4), and API keys (task 5) land
# here; audit append and ``provision_user`` followed in task 6 and
# ``provision_organization`` in task 7 — with all 19 protocol methods present
# the adapter satisfies the runtime-checkable ``Storage`` protocol.
# ---------------------------------------------------------------------------


def _put_if_absent(
    table: str, item: Mapping[str, Any], key_attributes: Sequence[str]
) -> dict[str, Any]:
    """One ``Put`` transact item that fails when the record key already exists.

    ``attribute_not_exists`` on the key attribute(s) is DynamoDB's PRIMARY KEY
    collision (decision 2: native on the record-id tables, and the mechanism the
    ``unique_constraints`` items use to enforce a domain uniqueness).
    """
    names = {f"#{name}": name for name in key_attributes}
    condition = " AND ".join(f"attribute_not_exists(#{name})" for name in key_attributes)
    return {
        "Put": {
            "TableName": table,
            "Item": dict(item),
            "ConditionExpression": condition,
            "ExpressionAttributeNames": names,
        }
    }


def _parent_exists(table: str, key: Mapping[str, Any]) -> dict[str, Any]:
    """One ``ConditionCheck`` transact item that fails when the parent is missing.

    This is how DynamoDB replicates a SQLite foreign key with no
    read-before-write TOCTOU window (contract docstring: the check belongs
    inside the conditional write).
    """
    names = {f"#{name}": name for name in key}
    condition = " AND ".join(f"attribute_exists(#{name})" for name in key)
    return {
        "ConditionCheck": {
            "TableName": table,
            "Key": dict(key),
            "ConditionExpression": condition,
            "ExpressionAttributeNames": names,
        }
    }


class DynamoDbStorage:
    """DynamoDB-backed :class:`~app.storage.contract.Storage` adapter.

    Construct through :func:`open_dynamodb_storage` (the documented factory);
    application code is typed against the ``Storage`` protocol only. The
    injected ``resource`` is the unit-test seam (a fake resource constructs
    without any network call); ``close()`` shuts the underlying client down and
    makes the instance unusable (reuse raises :class:`StorageError`).
    """

    def __init__(self, *, resource: Any, table_prefix: str = "") -> None:
        self._resource = resource
        self._table_prefix = table_prefix
        self._closed = False

    @property
    def table_prefix(self) -> str:
        """Prefix applied to every schema table name (environment isolation)."""
        return self._table_prefix

    # -- resource access -----------------------------------------------------

    def _table_name(self, name: str) -> str:
        """Qualified (prefixed) name of one :data:`SCHEMA` table.

        An unknown name is a programming error inside the adapter, never a
        driver-level ``ResourceNotFoundException``: it fails loudly here with a
        fixed message.
        """
        if name not in _SCHEMA_TABLE_NAMES:
            raise StorageError(f"the adapter has no table named {name!r}")
        return f"{self._table_prefix}{name}"

    def _table(self, name: str) -> Any:
        """The boto3 ``Table`` for one :data:`SCHEMA` table under this prefix."""
        if self._closed:
            raise StorageError("this storage adapter instance is closed")
        return self._resource.Table(self._table_name(name))

    def _client(self) -> Any:
        """The boto3 client behind the injected resource (transactional writes).

        Reached through the resource so the high-level (de)serialization
        registered by boto3 applies uniformly: items are plain Python values on
        the way in and plain Python values on the way out.
        """
        if self._closed:
            raise StorageError("this storage adapter instance is closed")
        return self._resource.meta.client

    def _get(self, table: str, key: Mapping[str, Any]) -> dict[str, Any] | None:
        """One strongly consistent point read; ``None`` when the item is absent.

        ``ConsistentRead=True`` is what preserves SQLite's read-your-writes
        parity: an eventually consistent ``GetItem`` could answer a just-committed
        ``TransactWriteItems`` with a miss (the identity lookup after provisioning,
        the stored truth after a revocation CAS), which the contract does not
        allow. DynamoDB Local is always strongly consistent, so only the
        explicit flag carries the guarantee to production.
        """
        item: dict[str, Any] | None = (
            self._table(table).get_item(Key=dict(key), ConsistentRead=True).get("Item")
        )
        return item

    def _transact(
        self,
        items: Sequence[Mapping[str, Any]],
        descriptors: Sequence[ConflictDescriptor],
    ) -> None:
        """Submit one ``TransactWriteItems`` with bounded transient retry.

        The submitted items and the descriptors are positionally aligned
        (decision 3), so a cancellation classifies by submission order. Driver
        exceptions never escape: only :class:`StorageError` subclasses do.
        """
        client = self._client()
        transact_items = list(items)

        def submit() -> None:
            client.transact_write_items(TransactItems=transact_items)

        execute_transaction(submit, descriptors)

    def _put(
        self, table: str, item: Mapping[str, Any], key_attributes: Sequence[str]
    ) -> dict[str, Any]:
        """One :func:`_put_if_absent` item, qualified with this adapter's prefix.

        Operations always name the *schema* table; prefixing happens here so no
        call site can write to an unqualified table.
        """
        return _put_if_absent(self._table_name(table), item, key_attributes)

    def _check_parent(self, table: str, key: Mapping[str, Any]) -> dict[str, Any]:
        """One :func:`_parent_exists` item, qualified with this adapter's prefix."""
        return _parent_exists(self._table_name(table), key)

    # -- Users and external identities (task 3) ------------------------------

    def create_user(self, user: User) -> User:
        """Persist a new user and echo the caller-supplied entity back.

        Storage mints nothing: the item is exactly ``user``. The base put and
        the ``user_email`` constraint put go in **one** transaction, so a
        rejected write leaves neither row behind (SQLite's rollback equivalent).
        A taken email surfaces as ``kind="user_email"`` and a ``usr_`` id
        collision as ``kind="entity_id"``, both translated positionally
        (decision 3); submission order mirrors SQLite's statement order.
        """
        self._transact(
            [
                self._put("users", user_item(user), ("pk",)),
                self._put(
                    "unique_constraints",
                    user_email_constraint_item(user),
                    ("pk",),
                ),
            ],
            [
                DuplicateConflict(DuplicateEntityKind.ENTITY_ID),
                DuplicateConflict(DuplicateEntityKind.USER_EMAIL),
            ],
        )
        return user

    def get_user(self, user_id: UserId) -> User:
        """Load a user by ``usr_`` identity; a miss raises ``EntityNotFoundError``."""
        item = self._get("users", {"pk": str(user_id)})
        if item is None:
            raise EntityNotFoundError(f"no user with id {user_id!r}")
        return user_from_item(item)

    def create_external_identity(self, identity: ExternalIdentity) -> ExternalIdentity:
        """Attach a provider identity to an existing user (caller-echo).

        One transaction: base put (``extid_`` record id), the normalized
        ``(provider, subject, tenant)`` constraint put, and the
        ``users`` parent ``ConditionCheck``. So a duplicate tuple is
        ``kind="external_identity"`` (with ``None`` and ``''`` the *same*
        tuple, per the normalization), a duplicate record id ``kind="entity_id"``,
        and an unknown ``user_id`` :class:`ReferenceNotFoundError` — and none of
        them leaves a partial row.
        """
        self._transact(
            [
                self._put("external_identities", external_identity_item(identity), ("pk",)),
                self._put(
                    "unique_constraints",
                    external_identity_constraint_item(identity),
                    ("pk",),
                ),
                self._check_parent("users", {"pk": str(identity.user_id)}),
            ],
            [
                DuplicateConflict(DuplicateEntityKind.ENTITY_ID),
                DuplicateConflict(DuplicateEntityKind.EXTERNAL_IDENTITY),
                ReferenceConflict(),
            ],
        )
        return identity

    def get_user_by_external_identity(
        self,
        *,
        provider: IdentityProvider,
        provider_subject: ProviderSubject,
        provider_tenant: ProviderTenant | None = None,
    ) -> User:
        """Resolve the identity tuple to the internal :class:`User`.

        Two point reads on the key-only constraint table and the ``users`` base
        table (decision 2): the constraint ``GetItem`` supplies the owning
        ``user_id``, the user ``GetItem`` supplies the payload. The provider
        subject is therefore never compared against a ``usr_`` id, and the
        tenant is normalized the same way writes store it. A miss on either read
        raises :class:`EntityNotFoundError` — Phase 03's "needs provisioning"
        signal, never a ``None`` return.
        """
        constraint = self._get(
            "unique_constraints",
            {
                "pk": encode_constraint_key(
                    ConstraintKind.EXTERNAL_IDENTITY,
                    encode_external_identity_value(provider, provider_subject, provider_tenant),
                )
            },
        )
        if constraint is None:
            raise EntityNotFoundError("no external identity matches the given tuple")
        user_id = constraint.get("user_id")
        if not isinstance(user_id, str):
            # A constraint item without its owning user is corrupt store data,
            # not a lookup miss: fail loudly, never guess.
            raise StorageError("external identity constraint item is malformed")
        item = self._get("users", {"pk": user_id})
        if item is None:
            raise EntityNotFoundError("no external identity matches the given tuple")
        return user_from_item(item)

    # -- List-read helpers (task 4, decision 5) ------------------------------

    def _decode_resume(
        self,
        scope: str,
        cursor: str,
        resume_keys: tuple[str, ...],
    ) -> dict[str, str]:
        """Decode a cursor and pin its resume attributes to one index's key set.

        :func:`decode_cursor` already rejects malformed, tampered, and
        foreign-scope payloads; the attribute-name check additionally keeps a
        hand-forged (right-scope, wrong-shape) token from ever reaching the
        driver as an invalid ``ExclusiveStartKey``.
        """
        resume = decode_cursor(scope, cursor)
        if set(resume) != set(resume_keys):
            raise InvalidCursorError("cursor payload is malformed")
        return resume

    def _query_matches(
        self,
        table: str,
        *,
        index_name: str,
        key_condition: str,
        filter_expression: str | None,
        expression_names: Mapping[str, str],
        expression_values: Mapping[str, Any],
        resume: Mapping[str, str] | None,
        stop_after: int,
    ) -> list[dict[str, Any]]:
        """Accumulate GSI matches until ``stop_after`` items or exhaustion.

        Each ``Query`` evaluates ``SCAN_BATCH`` items server-side (the filter
        runs before items come back, so filtered continuation relies on the
        keyset resume from the last *returned* match, never on
        ``LastEvaluatedKey``); the loop keeps paging until the caller's
        ``limit + 1`` accumulation is met or the segment ends — the probe-row
        pattern shared with SQLite's ``_build_page``. Index queries cannot
        request consistent reads (DynamoDB rejects the flag on a GSI);
        DynamoDB Local answers strongly consistent, and production GSI
        replication lag is a documented Phase 06 limitation.
        """
        query_table = self._table(table)
        items: list[dict[str, Any]] = []
        start_key: dict[str, Any] | None = dict(resume) if resume is not None else None
        while True:
            kwargs: dict[str, Any] = {
                "IndexName": index_name,
                "KeyConditionExpression": key_condition,
                "ExpressionAttributeNames": dict(expression_names),
                "ExpressionAttributeValues": dict(expression_values),
                "Limit": SCAN_BATCH,
            }
            if filter_expression is not None:
                kwargs["FilterExpression"] = filter_expression
            if start_key is not None:
                kwargs["ExclusiveStartKey"] = start_key
            try:
                response = query_table.query(**kwargs)
            except ClientError:
                raise StorageError("storage query failed") from None
            items.extend(response.get("Items", []))
            start_key = response.get("LastEvaluatedKey")
            if len(items) >= stop_after or start_key is None:
                return items

    @staticmethod
    def _resume_key(item: Mapping[str, Any], resume_keys: tuple[str, ...]) -> dict[str, str]:
        """The resume payload for one returned item: exactly its key attributes."""
        return {name: str(item[name]) for name in resume_keys}

    def _read_back_organizations(self, organization_ids: Sequence[str]) -> list[Organization]:
        """Fetch one page's organizations with a single ``BatchGetItem``.

        Decision 2's batch-boundary rule: only the **trimmed page's** ids are
        fetched (≤ ``MAX_PAGE_LIMIT`` keys, always inside the 100-key/4 MB
        caps; the probe row's organization is never fetched). Batch response
        order is not contractual, so items are re-keyed and the rebuilt
        organizations are returned in the GSI's ``(org_created_at, org_id)``
        order. A miss is impossible under the frozen contract (no
        organization-delete path) and becomes the base :class:`StorageError`
        with fixed text if ever observed; unprocessed keys are re-requested a
        bounded number of times.
        """
        if not organization_ids:
            return []
        table = self._table_name("organizations")
        client = self._client()
        remaining: list[dict[str, str]] = [{"pk": entity_id} for entity_id in organization_ids]
        found: dict[str, dict[str, Any]] = {}
        for _ in range(_BATCH_READ_MAX_ATTEMPTS):
            if not remaining:
                break
            try:
                response = client.batch_get_item(
                    RequestItems={table: {"Keys": remaining, "ConsistentRead": True}}
                )
            except ClientError:
                raise StorageError("storage batch read failed") from None
            for item in response.get("Responses", {}).get(table, []):
                found[str(item["pk"])] = item
            remaining = list(response.get("UnprocessedKeys", {}).get(table, {}).get("Keys", []))
        if remaining:
            raise StorageError("storage batch read did not complete")
        organizations: list[Organization] = []
        for entity_id in organization_ids:
            item = found.get(entity_id)
            if item is None:
                raise StorageError("an organization referenced by a membership could not be read")
            organizations.append(organization_from_item(item))
        return organizations

    # -- Organizations and memberships (task 4) ------------------------------

    def create_organization(self, organization: Organization) -> Organization:
        """Persist a new organization and echo the caller-supplied entity back.

        Storage mints nothing: the item is exactly ``organization``. One
        transaction: the ``org_`` base put and the ``organization_slug``
        constraint put (decision 2). A taken slug surfaces as
        ``kind="organization_slug"`` and an ``org_`` id collision as
        ``kind="entity_id"`` — base put first in submission order, mirroring
        SQLite, so a both-taken write reports the record id — and a rejected
        batch leaves no constraint row behind.
        """
        self._transact(
            [
                self._put("organizations", organization_item(organization), ("pk",)),
                self._put(
                    "unique_constraints",
                    organization_slug_constraint_item(organization),
                    ("pk",),
                ),
            ],
            [
                DuplicateConflict(DuplicateEntityKind.ENTITY_ID),
                DuplicateConflict(DuplicateEntityKind.ORGANIZATION_SLUG),
            ],
        )
        return organization

    def get_organization(self, organization_id: OrganizationId) -> Organization:
        """Load an organization by ``org_`` identity; a miss raises ``EntityNotFoundError``."""
        item = self._get("organizations", {"pk": str(organization_id)})
        if item is None:
            raise EntityNotFoundError(f"no organization with id {organization_id!r}")
        return organization_from_item(item)

    def create_membership(self, membership: Membership) -> Membership:
        """Grant a user a role in an organization (caller-echo).

        The ``(organization, user)`` pair is **native** (base keys), so a
        re-grant is a base-put condition failure mapped to
        ``kind="membership"``; the ``mem_`` record id is guarded by a
        constraint item mapped to ``kind="entity_id"``. Both parents are
        enforced with ``ConditionCheck``s (the contract's DynamoDB
        foreign-key obligation). The organization is read **first** only to
        denormalize ``g_org_created`` (decision 2: the by-user index orders
        by organization creation time); the org ``ConditionCheck`` still
        re-verifies existence inside the transaction, so the read informs the
        item, it never enforces the reference.
        """
        organization = self._get("organizations", {"pk": str(membership.organization_id)})
        if organization is None:
            raise ReferenceNotFoundError("a referenced parent record does not exist")
        organization_created_at = decode_timestamp(organization["created_at"])
        self._transact(
            [
                self._put(
                    "memberships",
                    membership_item(membership, organization_created_at),
                    ("organization_id", "user_id"),
                ),
                self._put(
                    "unique_constraints",
                    membership_id_constraint_item(membership),
                    ("pk",),
                ),
                self._check_parent("organizations", {"pk": str(membership.organization_id)}),
                self._check_parent("users", {"pk": str(membership.user_id)}),
            ],
            [
                DuplicateConflict(DuplicateEntityKind.MEMBERSHIP),
                DuplicateConflict(DuplicateEntityKind.ENTITY_ID),
                ReferenceConflict(),
                ReferenceConflict(),
            ],
        )
        return membership

    def get_membership(self, *, organization_id: OrganizationId, user_id: UserId) -> Membership:
        """Load the membership for one ``(organization, user)`` domain tuple.

        A native point read on the base table's key pair — any status
        resolves (this is the suspension check), the ``mem_`` record id never
        surfaces as a lookup key, and a miss raises
        :class:`EntityNotFoundError` (never ``None``).
        """
        item = self._get(
            "memberships",
            {"organization_id": str(organization_id), "user_id": str(user_id)},
        )
        if item is None:
            raise EntityNotFoundError("no membership for that (organization, user) tuple")
        return membership_from_item(item)

    def list_user_organizations(self, user_id: UserId, page: PageParams) -> Page[Organization]:
        """Page through organizations where the user holds an **active** membership.

        The ``by-user`` GSI (PK ``g_user``, SK ``g_org_created`` = organization
        ``created_at`` + ``#`` + org id) supplies ``(created_at, id)`` order
        server-side; a ``FilterExpression`` on the membership item's ``status``
        hides non-active memberships DynamoDB-side (decision 2: keyset
        semantics make filtered continuation correct). The page payload lives
        on the ``organizations`` table, so the trimmed page's org ids go
        through one ``BatchGetItem`` read-back reassembled in GSI order
        (decision 2's batch-boundary rule). The cursor resumes from the last
        **returned** membership item's four key attributes.
        """
        limit = clamp_limit(page.limit)
        resume = (
            self._decode_resume(
                CURSOR_SCOPE_USER_ORGANIZATIONS,
                page.cursor,
                _USER_ORGANIZATIONS_RESUME_KEYS,
            )
            if page.cursor is not None
            else None
        )
        items = self._query_matches(
            "memberships",
            index_name="by-user",
            key_condition="#g_user = :user_id",
            filter_expression="#status = :active_status",
            expression_names={"#g_user": "g_user", "#status": "status"},
            expression_values={
                ":user_id": str(user_id),
                ":active_status": str(MembershipStatus.ACTIVE),
            },
            resume=resume,
            stop_after=limit + 1,
        )
        has_more = len(items) > limit
        page_items = items[:limit]
        next_cursor = (
            encode_cursor(
                CURSOR_SCOPE_USER_ORGANIZATIONS,
                self._resume_key(page_items[-1], _USER_ORGANIZATIONS_RESUME_KEYS),
            )
            if has_more and page_items
            else None
        )
        organizations = self._read_back_organizations(
            [str(item["organization_id"]) for item in page_items]
        )
        return Page(items=organizations, limit=limit, next_cursor=next_cursor)

    def list_memberships(
        self,
        organization_id: OrganizationId,
        page: PageParams,
    ) -> Page[Membership]:
        """Page through one organization's memberships (all statuses).

        The ``by-organization`` GSI (SK = membership ``created_at`` + ``#`` +
        ``mem_`` id) carries the full payload (``ALL`` projection), so there
        is no read-back; the partition key pins the organization scope
        server-side, so another organization's memberships can never appear.
        Same keyset discipline as :meth:`list_user_organizations` minus the
        status filter.
        """
        limit = clamp_limit(page.limit)
        resume = (
            self._decode_resume(
                CURSOR_SCOPE_MEMBERSHIPS,
                page.cursor,
                _MEMBERSHIPS_RESUME_KEYS,
            )
            if page.cursor is not None
            else None
        )
        items = self._query_matches(
            "memberships",
            index_name="by-organization",
            key_condition="#g_org = :organization_id",
            filter_expression=None,
            expression_names={"#g_org": "g_org"},
            expression_values={":organization_id": str(organization_id)},
            resume=resume,
            stop_after=limit + 1,
        )
        has_more = len(items) > limit
        page_items = items[:limit]
        next_cursor = (
            encode_cursor(
                CURSOR_SCOPE_MEMBERSHIPS,
                self._resume_key(page_items[-1], _MEMBERSHIPS_RESUME_KEYS),
            )
            if has_more and page_items
            else None
        )
        return Page(
            items=[membership_from_item(item) for item in page_items],
            limit=limit,
            next_cursor=next_cursor,
        )

    def delete_membership(self, *, organization_id: OrganizationId, user_id: UserId) -> None:
        """Physically remove one ``(organization, user)`` membership.

        A conditional ``DeleteItem`` on the native key pair: the condition
        failing means the item was absent, which raises
        :class:`EntityNotFoundError` — removal is explicitly **not**
        idempotent (SQLite's blocked-then-zero-rowcount path; the single-item
        conditional discipline is decision 4's, shared with task 5's
        revocation CAS). Only the base item is removed: the breakdown pins a
        single conditional delete, and the suite's re-grant-after-delete case
        uses a fresh ``mem_`` id, so the guard item's lifetime is unobserved
        (noted for the Phase 08 hardening list).
        """
        memberships_table = self._table("memberships")
        key = {"organization_id": str(organization_id), "user_id": str(user_id)}

        def submit() -> None:
            memberships_table.delete_item(
                Key=key,
                ConditionExpression=(
                    "attribute_exists(#organization_id) AND attribute_exists(#user_id)"
                ),
                ExpressionAttributeNames={
                    "#organization_id": "organization_id",
                    "#user_id": "user_id",
                },
            )

        if not execute_conditional_write(submit):
            raise EntityNotFoundError("no membership for that (organization, user) tuple")

    # -- API keys (task 5) -----------------------------------------------------

    def create_api_key(self, api_key: ApiKey) -> ApiKey:
        """Persist a new API-key credential row (caller-echo).

        Storage mints nothing: the item is exactly ``api_key``. One
        transaction: the ``key_`` base put, the §8 ``api_key_id`` segment
        constraint put, and the organization/creator ``ConditionCheck``s that
        replicate SQLite's foreign keys (contract: api_key→organization+creator,
        checked in that column order). So a taken segment is
        ``kind="api_key_id"``, a ``key_`` record-id collision is
        ``kind="entity_id"`` (base put first in submission order, mirroring
        SQLite, so a both-taken write reports the record id), and an unknown
        organization or creator is :class:`ReferenceNotFoundError` — none of
        them leaves a partial row. ``scopes`` round-trip exactly (order and
        duplicates preserved; normalization is Phase 05 domain work).
        """
        self._transact(
            [
                self._put("api_keys", api_key_item(api_key), ("pk",)),
                self._put(
                    "unique_constraints",
                    api_key_id_constraint_item(api_key),
                    ("pk",),
                ),
                self._check_parent("organizations", {"pk": str(api_key.organization_id)}),
                self._check_parent("users", {"pk": str(api_key.created_by_user_id)}),
            ],
            [
                DuplicateConflict(DuplicateEntityKind.ENTITY_ID),
                DuplicateConflict(DuplicateEntityKind.API_KEY_ID),
                ReferenceConflict(),
                ReferenceConflict(),
            ],
        )
        return api_key

    def get_api_key(self, api_key_id: ApiKeyId) -> ApiKey:
        """Load a key by its ``key_`` application identity; a miss raises ``EntityNotFoundError``.

        Tenancy is deliberately **not** filtered here (contract-pinned): the §8
        verification path must resolve the organization *from* the key, so the
        full item is returned regardless of organization and enforcing the §14
        org-scoped route contract is the Phase 05 service's check of
        ``api_key.organization_id``, not a storage filter. ``api_key_id`` is the
        ``key_`` identity — not the §8 credential segment (see
        :meth:`get_api_key_by_key_id`).
        """
        item = self._get("api_keys", {"pk": str(api_key_id)})
        if item is None:
            raise EntityNotFoundError(f"no api key with id {api_key_id!r}")
        return api_key_from_item(item)

    def get_api_key_by_key_id(self, key_id: KeyId) -> ApiKey:
        """Load a key by the §8 non-secret ``<key-id>`` credential segment.

        Two point reads on the key-only constraint table and the ``api_keys``
        base table (decision 2): the constraint ``GetItem`` by
        ``api_key_id#<segment>`` supplies the ``key_`` id, the key ``GetItem``
        supplies the payload. Returns stored truth: after revocation the row
        still resolves with ``status=revoked`` and ``revoked_at`` set, because
        status is data and rejection is Phase 05 verification work. A miss on
        either read raises :class:`EntityNotFoundError` — never ``None``.
        """
        constraint = self._get(
            "unique_constraints",
            {"pk": encode_constraint_key(ConstraintKind.API_KEY_ID, key_id)},
        )
        if constraint is None:
            raise EntityNotFoundError("no api key carries that credential segment")
        entity_id = constraint.get("entity_id")
        if not isinstance(entity_id, str):
            # A constraint item without its guarded key id is corrupt store
            # data, not a lookup miss: fail loudly, never guess.
            raise StorageError("api key constraint item is malformed")
        item = self._get("api_keys", {"pk": entity_id})
        if item is None:
            raise EntityNotFoundError("no api key carries that credential segment")
        return api_key_from_item(item)

    def list_api_keys(self, organization_id: OrganizationId, page: PageParams) -> Page[ApiKey]:
        """Page through one organization's API keys (all statuses).

        The ``by-organization`` GSI (PK ``g_org``, SK ``g_created`` =
        ``created_at`` + ``#`` + ``key_`` id) carries the full payload
        (``ALL`` projection), so there is no read-back; the partition key pins
        the organization scope server-side, so another organization's keys can
        never appear. Same keyset discipline as :meth:`list_memberships` — no
        status filter, revoked keys are listed.
        """
        limit = clamp_limit(page.limit)
        resume = (
            self._decode_resume(
                CURSOR_SCOPE_API_KEYS,
                page.cursor,
                _API_KEYS_RESUME_KEYS,
            )
            if page.cursor is not None
            else None
        )
        items = self._query_matches(
            "api_keys",
            index_name="by-organization",
            key_condition="#g_org = :organization_id",
            filter_expression=None,
            expression_names={"#g_org": "g_org"},
            expression_values={":organization_id": str(organization_id)},
            resume=resume,
            stop_after=limit + 1,
        )
        has_more = len(items) > limit
        page_items = items[:limit]
        next_cursor = (
            encode_cursor(
                CURSOR_SCOPE_API_KEYS,
                self._resume_key(page_items[-1], _API_KEYS_RESUME_KEYS),
            )
            if has_more and page_items
            else None
        )
        return Page(
            items=[api_key_from_item(item) for item in page_items],
            limit=limit,
            next_cursor=next_cursor,
        )

    def revoke_api_key(self, api_key_id: ApiKeyId, *, revoked_at: UtcDatetime) -> ApiKey:
        """Transition a key ``active → revoked`` (first-write-wins CAS).

        Decision 4 mirrors the SQLite statement field-for-field
        (``sqlite.py:1148-1156`` sets exactly ``status`` and ``revoked_at``;
        the model has no ``updated_at``): a standalone conditional
        ``UpdateItem`` with ``attribute_exists(pk) AND #status = 'active'``.
        ``revoked_at`` comes from the caller (storage never mints timestamps).
        On a CAS miss the operation reads stored truth: absent →
        :class:`EntityNotFoundError` (absence is absence — only the CAS is
        idempotent), present (already revoked by a racing or duplicate call) →
        the stored key with the **original** ``revoked_at`` preserved, an
        idempotent success, not an error. On a CAS hit the same strongly
        consistent read returns the just-written row — the same observable
        outcome as SQLite's blocked-then-zero-rowcount path.
        """
        api_keys_table = self._table("api_keys")
        key = {"pk": str(api_key_id)}

        def submit() -> None:
            api_keys_table.update_item(
                Key=key,
                ConditionExpression="attribute_exists(#pk) AND #status = :active_status",
                UpdateExpression="SET #status = :revoked_status, #revoked_at = :revoked_at",
                ExpressionAttributeNames={
                    "#pk": "pk",
                    "#status": "status",
                    "#revoked_at": "revoked_at",
                },
                ExpressionAttributeValues={
                    ":active_status": str(ApiKeyStatus.ACTIVE),
                    ":revoked_status": str(ApiKeyStatus.REVOKED),
                    ":revoked_at": encode_timestamp(revoked_at),
                },
            )

        if not execute_conditional_write(submit):
            item = self._get("api_keys", key)
            if item is None:
                raise EntityNotFoundError(f"no api key with id {api_key_id!r}")
            return api_key_from_item(item)
        item = self._get("api_keys", key)
        if item is None:
            # The CAS just committed this row and no key-delete path exists in
            # the frozen contract: absence here is impossible store corruption,
            # not a lookup miss (mirrors the read-back-miss rule of the
            # organization batch read).
            raise StorageError("an api key could not be read after revocation")
        return api_key_from_item(item)

    # -- Audit (task 6) --------------------------------------------------------

    def append_audit_event(self, audit_event: AuditEvent) -> None:
        """Append one fully formed audit event (standalone write path).

        Returns ``None`` — storage mints nothing and re-reads nothing, so there
        is nothing to return (contract-pinned). One transaction: the ``aud_``
        base put (record-id conflicts are native on this table, decision 2 — a
        re-append is ``kind="entity_id"``, never a raw driver error) and the
        organizations ``ConditionCheck`` replicating SQLite's audit→organization
        foreign key (the actor id is §10 application identity enforced at the
        model boundary, not an FK). Base put first in submission order,
        mirroring SQLite's insert (the PK is checked during the row insert, the
        FK after), so a both-bad append reports the record id; a rejected
        append leaves no row. There is no audit read or list surface in this
        phase: append is write-only by contract, and ``metadata`` round-trips
        exactly through the native-M storage of :func:`audit_event_item`.
        """
        self._transact(
            [
                self._put("audit_events", audit_event_item(audit_event), ("pk",)),
                self._check_parent("organizations", {"pk": str(audit_event.organization_id)}),
            ],
            [
                DuplicateConflict(DuplicateEntityKind.ENTITY_ID),
                ReferenceConflict(),
            ],
        )

    # -- Compound provisioning (tasks 6 and 7) --------------------------------

    def _resolve_race_winner(
        self,
        reasons: Sequence[Mapping[str, Any]],
        race_constraint_pk_by_index: Mapping[int, str],
    ) -> UserId | None:
        """Resolve the §6 race winner's ``usr_`` id after the rollback.

        One strongly consistent ``GetItem`` on the **winning** constraint item
        (decision 3): the failing item is located with the same positional rule
        that decided the error (first ``ConditionalCheckFailed`` in submission
        order), the key-only constraint table (decision 2) carries the owner's
        ``user_id`` on the email and identity-tuple items, and the constraint
        ``pk`` is fully known from the failed write's own inputs — so the
        winner resolves in one read, the analogue of SQLite's post-rollback
        identity-then-email fallback reads. The transaction cancelled and
        rolled back completely before this read, so it sees the *concurrent
        winner's* committed rows. Anything unresolvable yields ``None``
        (contract: "when the adapter can resolve it, else ``None``") — never a
        second error masking the race.
        """
        for index, reason in enumerate(reasons):
            if reason.get("Code") == _CONDITIONAL_CHECK_FAILED:
                constraint_pk = race_constraint_pk_by_index.get(index)
                if constraint_pk is None:
                    return None
                constraint = self._get("unique_constraints", {"pk": constraint_pk})
                if constraint is None:
                    return None
                winner_user_id = constraint.get("user_id")
                if not isinstance(winner_user_id, str):
                    return None
                try:
                    return UserId(winner_user_id)
                except ValueError:
                    # Corrupt constraint data: best-effort resolution yields
                    # None rather than replacing the pinned race error.
                    return None
        return None

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
        audit events in one ``TransactWriteItems`` (spec §6/§12, decision 3).

        Submission order mirrors SQLite's statement order — users → identities
        → organizations → memberships → audits, each group base put then
        constraint put — so a multi-failure race classifies identically on both
        adapters, and the parallel, same-ordered descriptors map each cancelled
        item to its domain error (the first ``ConditionalCheckFailed`` decides).
        The membership item denormalizes the ``created_at`` of the organization
        the membership actually points at onto ``g_org_created`` (decision 2:
        the batch's own organization supplies it; an external organization is
        read before the transaction, mirroring ``create_membership``'s
        read-informs/check-enforces split). Parents the batch
        creates itself need no ``ConditionCheck`` (transaction conditions see
        only committed data, and the batch's own puts supply the rows); a child
        referencing a parent *outside* the batch — an identity owned by another
        user, a membership into another organization, an audit event in another
        organization — gets one, deduplicated by table+key because a
        transaction may touch an item only once. This is the contract's "a
        cross-check reveals a parent the batch does not itself create"
        obligation and the DynamoDB replication of SQLite's foreign keys.

        Conflict semantics (contract-pinned): an email **or** identity-tuple
        constraint failure is spec §6's concurrent-first-login race — never a
        plain email conflict — and surfaces as
        :class:`~app.storage.contract.DuplicateExternalIdentityError` after the
        full rollback (transactions are all-or-nothing, so no partial row of
        the rejected batch survives), with ``existing_user_id`` resolved by one
        constraint-item ``GetItem`` (:meth:`_resolve_race_winner`). Slug,
        membership-pair, and record-id failures propagate as their own
        :class:`DuplicateEntityError` kinds. Transient ``TransactionConflict``
        cancellations re-run the whole transaction (the SQLite
        ``busy_timeout`` analogue) until the racing loser converges on the
        winner's committed rows. Duplicate record ids *within one batch* (two
        events sharing an ``aud_`` id) are caller misuse SQLite reports as an
        ``entity_id`` conflict; a transaction may not touch one item twice, so
        DynamoDB rejects the request outright and it surfaces as the base
        :class:`~app.storage.contract.StorageError` — still leak-free, still
        zero residue. The returned bundle echoes the caller-supplied
        objects unchanged (caller-echo contract: storage mints nothing and does
        not re-read what it wrote).
        """
        # Materialize once: the item loop and the caller-echo tuple below must
        # share one iteration (a one-shot argument would otherwise persist rows
        # but echo an empty batch — the SQLite provision_user discipline).
        events = tuple(audit_events)
        # The membership's by-user sort key must carry the created_at of the
        # organization the membership ACTUALLY points at (SQLite's join orders
        # by the true org). The batch's own organization supplies it; a
        # membership into an external organization gets that org's stored
        # created_at read before the transaction — the same "read informs the
        # item, the ConditionCheck enforces the reference" discipline as
        # create_membership, and a read miss is the same ReferenceNotFoundError
        # the FK would reject (no batch row was written yet, so nothing to roll
        # back).
        if membership.organization_id != organization.id:
            external_org = self._get("organizations", {"pk": str(membership.organization_id)})
            if external_org is None:
                raise ReferenceNotFoundError("a referenced parent record does not exist")
            membership_organization_created_at = decode_timestamp(external_org["created_at"])
        else:
            membership_organization_created_at = organization.created_at
        email_constraint = user_email_constraint_item(user)
        identity_constraint = external_identity_constraint_item(identity)
        items: list[dict[str, Any]] = [
            self._put("users", user_item(user), ("pk",)),
            self._put("unique_constraints", email_constraint, ("pk",)),
            self._put("external_identities", external_identity_item(identity), ("pk",)),
            self._put("unique_constraints", identity_constraint, ("pk",)),
            self._put("organizations", organization_item(organization), ("pk",)),
            self._put(
                "unique_constraints",
                organization_slug_constraint_item(organization),
                ("pk",),
            ),
            self._put(
                "memberships",
                membership_item(membership, membership_organization_created_at),
                ("organization_id", "user_id"),
            ),
            self._put(
                "unique_constraints",
                membership_id_constraint_item(membership),
                ("pk",),
            ),
        ]
        descriptors: list[ConflictDescriptor] = [
            DuplicateConflict(DuplicateEntityKind.ENTITY_ID),
            IdentityRaceConflict(),
            DuplicateConflict(DuplicateEntityKind.ENTITY_ID),
            IdentityRaceConflict(),
            DuplicateConflict(DuplicateEntityKind.ENTITY_ID),
            DuplicateConflict(DuplicateEntityKind.ORGANIZATION_SLUG),
            DuplicateConflict(DuplicateEntityKind.MEMBERSHIP),
            DuplicateConflict(DuplicateEntityKind.ENTITY_ID),
        ]
        for event in events:
            items.append(self._put("audit_events", audit_event_item(event), ("pk",)))
            descriptors.append(DuplicateConflict(DuplicateEntityKind.ENTITY_ID))
        # Race winner resolution (decision 3): the constraint PK is fully known
        # from the failed write's own inputs, and the positional rule that
        # decided the error identifies which race item failed. When the email
        # and the identity tuple collide for *different* users (the contract
        # leaves "the winner" unspecified there and the suite never constructs
        # it), submission order resolves the email item's owner — §6's real
        # race carries one email and one tuple for the same winner.
        race_constraint_pk_by_index: dict[int, str] = {
            index: str(items[index]["Put"]["Item"]["pk"])
            for index, descriptor in enumerate(descriptors)
            if isinstance(descriptor, IdentityRaceConflict)
        }
        # External-parent ConditionChecks go last (decision 3), deduplicated by
        # table+key: a transaction may operate on one item only once.
        external_parents: dict[tuple[str, str], None] = {}
        if identity.user_id != user.id:
            external_parents[("users", str(identity.user_id))] = None
        if membership.organization_id != organization.id:
            external_parents[("organizations", str(membership.organization_id))] = None
        if membership.user_id != user.id:
            external_parents[("users", str(membership.user_id))] = None
        for event in events:
            if event.organization_id != organization.id:
                external_parents[("organizations", str(event.organization_id))] = None
        for table, parent_pk in external_parents:
            items.append(self._check_parent(table, {"pk": parent_pk}))
            descriptors.append(ReferenceConflict())

        # The retry loop mirrors execute_transaction's bounded-transient
        # discipline; it is inlined because the race converge needs the raw
        # CancellationReasons (which race item failed decides the single
        # winner-resolution GetItem), which the shared helper does not surface.
        client = self._client()
        transact_items = list(items)
        for _ in range(MAX_TRANSACTION_ATTEMPTS):
            try:
                client.transact_write_items(TransactItems=transact_items)
                break
            except ClientError as exc:
                verdict = classify_client_error(exc, descriptors)
                if isinstance(verdict, _RetrySentinel):
                    continue
                if isinstance(verdict, DuplicateExternalIdentityError):
                    reasons: Sequence[Mapping[str, Any]] = exc.response.get(
                        "CancellationReasons", []
                    )
                    raise DuplicateExternalIdentityError(
                        existing_user_id=self._resolve_race_winner(
                            reasons, race_constraint_pk_by_index
                        )
                    ) from None
                raise verdict from None
        else:
            raise StorageError("storage transaction aborted by concurrent activity")
        return ProvisionedUser(
            user=user,
            identity=identity,
            organization=organization,
            membership=membership,
            audit_events=events,
        )

    def provision_organization(
        self,
        *,
        organization: Organization,
        membership: Membership,
        audit_events: Sequence[AuditEvent],
    ) -> ProvisionedOrganization:
        """Atomically write organization + membership + audit events in one
        ``TransactWriteItems`` (Phase 04 breakdown decision 2, decision 3).

        Submission order mirrors SQLite's statement order — organizations →
        memberships → audits, each group base put then constraint put — with
        the parent ``ConditionCheck``s last, so a multi-failure race classifies
        identically on both adapters: the ``org_`` base put maps to
        ``kind="entity_id"``, the ``organization_slug`` constraint to
        ``kind="organization_slug"``, the membership base put to
        ``kind="membership"`` (the native org/user pair), the ``membership_id``
        guard to ``kind="entity_id"``, and every ``aud_`` base put to
        ``kind="entity_id"``. The membership item denormalizes the
        ``created_at`` of the organization it actually points at onto
        ``g_org_created`` (decision 2: the batch's own organization supplies
        it; an external organization is read before the transaction — the same
        "read informs the item, the ConditionCheck enforces the reference"
        split as ``create_membership`` and ``provision_user``). The batch's own
        organization needs no ``ConditionCheck`` (transaction conditions see
        only committed data, and a transaction may not touch one item twice —
        the batch's own puts supply the rows); the membership's **user** is the
        only parent this compound never creates, so it always gets a users
        ``ConditionCheck``, and any audit event or membership pointing at an
        organization *outside* the batch gets one too, deduplicated by
        table+key.

        Conflict semantics deliberately differ from :meth:`provision_user`
        **on purpose** (contract-pinned): there is no race convergence here. A
        taken slug is a plain :class:`DuplicateEntityError`
        (``kind="organization_slug"``) — never the identity-race error — and
        there is no winner-resolution read. Transient
        ``TransactionConflict`` cancellations re-run the whole transaction (the
        SQLite ``busy_timeout`` analogue). Every failure path is fully
        rolled back by the transaction: no partial organization, membership,
        or audit rows survive a rejected batch. The returned bundle echoes
        the caller-supplied objects unchanged (caller-echo contract: storage
        mints nothing and does not re-read what it wrote).
        """
        # Materialize once: the item loop and the caller-echo tuple below must
        # share one iteration (a one-shot argument would otherwise persist rows
        # but echo an empty batch — the SQLite provision_organization discipline).
        events = tuple(audit_events)
        # The membership's by-user sort key must carry the created_at of the
        # organization the membership ACTUALLY points at (SQLite's join orders
        # by the true org). The batch's own organization supplies it; a
        # membership into an external organization gets that org's stored
        # created_at read before the transaction, and a read miss is the same
        # ReferenceNotFoundError the FK would reject (no batch row was written
        # yet, so nothing to roll back).
        if membership.organization_id != organization.id:
            external_org = self._get("organizations", {"pk": str(membership.organization_id)})
            if external_org is None:
                raise ReferenceNotFoundError("a referenced parent record does not exist")
            membership_organization_created_at = decode_timestamp(external_org["created_at"])
        else:
            membership_organization_created_at = organization.created_at
        items: list[dict[str, Any]] = [
            self._put("organizations", organization_item(organization), ("pk",)),
            self._put(
                "unique_constraints",
                organization_slug_constraint_item(organization),
                ("pk",),
            ),
            self._put(
                "memberships",
                membership_item(membership, membership_organization_created_at),
                ("organization_id", "user_id"),
            ),
            self._put(
                "unique_constraints",
                membership_id_constraint_item(membership),
                ("pk",),
            ),
        ]
        descriptors: list[ConflictDescriptor] = [
            DuplicateConflict(DuplicateEntityKind.ENTITY_ID),
            DuplicateConflict(DuplicateEntityKind.ORGANIZATION_SLUG),
            DuplicateConflict(DuplicateEntityKind.MEMBERSHIP),
            DuplicateConflict(DuplicateEntityKind.ENTITY_ID),
        ]
        for event in events:
            items.append(self._put("audit_events", audit_event_item(event), ("pk",)))
            descriptors.append(DuplicateConflict(DuplicateEntityKind.ENTITY_ID))
        # External-parent ConditionChecks go last (decision 3), deduplicated by
        # table+key: a transaction may operate on one item only once. The
        # membership's user is the one parent this compound never creates, so
        # it is always checked; organizations are checked only when referenced
        # from outside the batch (the batch's own org put supplies its row).
        external_parents: dict[tuple[str, str], None] = {
            ("users", str(membership.user_id)): None,
        }
        if membership.organization_id != organization.id:
            external_parents[("organizations", str(membership.organization_id))] = None
        for event in events:
            if event.organization_id != organization.id:
                external_parents[("organizations", str(event.organization_id))] = None
        for table, parent_pk in external_parents:
            items.append(self._check_parent(table, {"pk": parent_pk}))
            descriptors.append(ReferenceConflict())
        self._transact(items, descriptors)
        return ProvisionedOrganization(
            organization=organization,
            membership=membership,
            audit_events=events,
        )

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        """Release the underlying client. Not reusable after."""
        if self._closed:
            return
        self._closed = True
        client = getattr(getattr(self._resource, "meta", None), "client", None)
        shutdown = getattr(client, "close", None)
        if callable(shutdown):
            shutdown()


def open_dynamodb_storage(
    *,
    endpoint_url: str | None = None,
    region: str = "us-east-1",
    table_prefix: str = "",
    dynamodb_resource: Any | None = None,
) -> DynamoDbStorage:
    """Documented entry point for the DynamoDB adapter.

    All parameters are keyword-only (one ``*`` marker; a second bare ``*``
    mid-signature would be a ``SyntaxError``). ``dynamodb_resource`` is the
    injectable seam for unit tests and the Local harness; when omitted a boto3
    resource is built for ``endpoint_url``/``region`` (construction performs no
    network I/O). ``table_prefix`` lets Phase 07 parameterize ``dev``/``staging``
    /``prod`` and the harness isolate per-test tables.
    """
    resource = dynamodb_resource
    if resource is None:
        resource = boto3.resource(
            "dynamodb",
            endpoint_url=endpoint_url,
            region_name=region,
        )
    return DynamoDbStorage(resource=resource, table_prefix=table_prefix)


__all__ = [
    "CURSOR_SCOPE_API_KEYS",
    "CURSOR_SCOPE_MEMBERSHIPS",
    "CURSOR_SCOPE_USER_ORGANIZATIONS",
    "DUPLICATE_KIND_BY_CONSTRAINT",
    "MAX_TRANSACTION_ATTEMPTS",
    "RETRY",
    "SCAN_BATCH",
    "SCHEMA",
    "ConflictDescriptor",
    "ConstraintKind",
    "DynamoDbStorage",
    "IndexSpec",
    "TableSpec",
    "api_key_from_item",
    "api_key_id_constraint_item",
    "api_key_item",
    "audit_event_item",
    "classify_cancellation_reasons",
    "classify_client_error",
    "decode_cursor",
    "decode_provider_tenant",
    "decode_timestamp",
    "encode_constraint_key",
    "encode_cursor",
    "encode_external_identity_value",
    "encode_provider_tenant",
    "encode_sort_key",
    "encode_timestamp",
    "execute_conditional_write",
    "execute_transaction",
    "external_identity_constraint_item",
    "external_identity_from_item",
    "external_identity_item",
    "membership_from_item",
    "membership_id_constraint_item",
    "membership_item",
    "open_dynamodb_storage",
    "organization_from_item",
    "organization_item",
    "organization_slug_constraint_item",
    "user_email_constraint_item",
    "user_from_item",
    "user_item",
]
