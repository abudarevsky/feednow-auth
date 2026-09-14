"""Application ID minting for FeedNow internal identifiers (Phase 03 task 1,
extended by Phase 05 task 1).

This module discharges **Phase 03's half of the Phase 01 ID-generation
deferral**. Phase 01 shipped prefix-validating value types only and explicitly
postponed concrete generation strategies: "Concrete generation strategies
(entropy source, ULID-style ``key_id`` per spec §8) belong to owner phases
03/05" (:mod:`app.models.ids`). With Phase 05 task 1 the deferral is now
fully discharged, one half per owner phase:

- Owned here (Phase 03): ``usr_``, ``org_``, ``extid_``, ``mem_``, ``aud_``.
- Owned here since **Phase 05 task 1**: the ``key_`` application identity
  (:func:`new_api_key_id`) — the same ``prefix + "_" + uuid4().hex``
  strategy as every other application ID.
- **Not owned here:** the §8 ``key_id`` credential segment inside
  ``fn_live_<key-id>_<secret>`` lives in :mod:`app.auth.credentials`, not in
  this module, so credential entropy (ULID/CSPRNG) never masquerades as
  application-ID entropy.

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
    ApiKeyId,
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


def new_api_key_id() -> ApiKeyId:
    """Mint a new internal FeedNow API-key identity (``key_``).

    Phase 05 task 1 discharges this half of the Phase 01 deferral. It is the
    **application identity** of the credential row — deliberately distinct
    from the §8 ``key_id`` credential segment inside the literal, which is
    minted by :func:`app.auth.credentials.generate_key_id`.
    """
    return _mint(ApiKeyId)


__all__ = [
    "new_api_key_id",
    "new_audit_event_id",
    "new_external_identity_id",
    "new_membership_id",
    "new_organization_id",
    "new_user_id",
]
