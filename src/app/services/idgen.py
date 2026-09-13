"""Application ID minting for FeedNow internal identifiers (Phase 03 task 1).

This module discharges **Phase 03's half of the Phase 01 ID-generation
deferral**. Phase 01 shipped prefix-validating value types only and explicitly
postponed concrete generation strategies: "Concrete generation strategies
(entropy source, ULID-style ``key_id`` per spec §8) belong to owner phases
03/05" (:mod:`app.models.ids`). The owner split is unchanged and this module
implements only the Phase 03 side of it:

- Owned here (Phase 03): ``usr_``, ``org_``, ``extid_``, ``mem_``, ``aud_``.
- **Not owned here:** the ``key_`` application ID and the §8 ``key_id``
  credential segment inside ``fn_live_<key-id>_<secret>`` stay with **Phase
  05** (API-key credentials and scopes). No API-key minter is exported from
  this module, so Phase 05 cannot accidentally inherit a Phase 03 entropy
  contract for credential material.

Strategy (per the Phase 03 breakdown, planner decision "ID generation"):
``prefix + "_" + uuid.uuid4().hex`` — 32 lowercase hex characters, which
validate against :data:`app.models.ids.ID_SUFFIX_PATTERN` without widening the
frozen Phase 01 shape rules. ``uuid.uuid4()`` is backed by :mod:`secrets`, so
no new entropy dependency is introduced.

Boundary rules preserved here:

- Every minter takes **no arguments**: IDs are pure entropy and can never be
  derived from, or collide because of, email, a provider ``sub``, or a
  provider name (AGENTS.md: internal FeedNow IDs are the application
  identity; provider subjects are never identity inputs).
- Values are returned as the concrete typed value objects from
  :mod:`app.models.ids`, so prefix/shape validation stays the single source of
  truth in the model layer and this module cannot mint an invalid ID silently.
- Storage adapters mint nothing; callers build a batch with these functions and
  pass complete entities down (Phase 02 contract).
"""

from __future__ import annotations

import uuid

from app.models.ids import (
    ApplicationId,
    AuditEventId,
    ExternalIdentityId,
    MembershipId,
    OrganizationId,
    RecordId,
    UserId,
)


def _mint[IdClass: (ApplicationId, RecordId)](id_class: type[IdClass]) -> IdClass:
    """Build ``{prefix}_{uuid4 hex}`` and return it as ``id_class``.

    Construction goes through the value type itself, so the Phase 01 prefix and
    shape validation always applies.
    """
    return id_class(f"{id_class.prefix}_{uuid.uuid4().hex}")


def new_user_id() -> UserId:
    """Mint a new internal FeedNow user ID (``usr_``)."""
    return _mint(UserId)


def new_organization_id() -> OrganizationId:
    """Mint a new internal FeedNow organization ID (``org_``)."""
    return _mint(OrganizationId)


def new_external_identity_id() -> ExternalIdentityId:
    """Mint a new ExternalIdentity record ID (``extid_``). Internal only."""
    return _mint(ExternalIdentityId)


def new_membership_id() -> MembershipId:
    """Mint a new Membership record ID (``mem_``). Internal only."""
    return _mint(MembershipId)


def new_audit_event_id() -> AuditEventId:
    """Mint a new AuditEvent record ID (``aud_``). Internal only."""
    return _mint(AuditEventId)


__all__ = [
    "new_audit_event_id",
    "new_external_identity_id",
    "new_membership_id",
    "new_organization_id",
    "new_user_id",
]
