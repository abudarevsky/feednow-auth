"""Mint typed FeedNow application and record identifiers.

Application IDs use their model-defined prefix and a UUID4 hexadecimal suffix.
The separate ``key_id`` API-key credential segment has a ULID/CSPRNG generator
in ``app.auth.credentials``. See ``docs/contracts.md``.

Boundary rules preserved here:

- Every minter takes **no arguments**: IDs are pure entropy and can never be
  derived from, or collide because of, email, a provider ``sub``, or a
  provider name (AGENTS.md: internal FeedNow IDs are the application
  identity; provider subjects are never identity inputs).
- Values are returned as the concrete typed value objects from
  :mod:`app.models.ids`, so prefix/shape validation stays the single source of
  truth in the model layer and this module cannot mint an invalid ID silently.
- Storage adapters mint nothing; callers build a batch with these functions and
  pass complete entities down (storage contract).

Current behavior and invariants: ``docs/architecture.md``."""

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

    Construction goes through the value type itself, so the initial prefix and
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

    API-key discharges this half of the initial deferral. It is the
    **application identity** of the credential row — deliberately distinct
    from the credential contract ``key_id`` credential segment inside the literal, which is
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
