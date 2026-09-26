"""Domain enumerations for the FeedNow identity model.

Values are **pinned** by the Phase 01 breakdown (Planner decisions): the spec
names these concepts but does not enumerate them, Phase 02 stores them as
strings, and Phase 05 branches on them. Renaming or adding a value is a
contract change and requires a spec revision.

All enums are :class:`~enum.StrEnum`s, so they validate from and serialize to
their exact lowercase string values (JSON round-trips are plain strings;
unknown strings are rejected by Pydantic).
"""

from __future__ import annotations

from enum import StrEnum


class UserStatus(StrEnum):
    """Lifecycle of a :class:`~app.models.user.User` account."""

    ACTIVE = "active"
    DISABLED = "disabled"


class OrganizationStatus(StrEnum):
    """Lifecycle of an :class:`~app.models.organization.Organization`."""

    ACTIVE = "active"
    DISABLED = "disabled"


class OrganizationNameStatus(StrEnum):
    """Whether an organization name is an initial placeholder or user-confirmed."""

    PLACEHOLDER = "placeholder"
    CONFIRMED = "confirmed"


class MembershipStatus(StrEnum):
    """Status of a :class:`~app.models.membership.Membership`.

    Removing a member is a **physical delete** (the storage contract already
    exposes ``delete_membership``); ``DISABLED`` is a temporary suspension,
    not the removal state.
    """

    ACTIVE = "active"
    DISABLED = "disabled"


class ApiKeyStatus(StrEnum):
    """Stored status of an API key credential.

    Only ``ACTIVE``/``REVOKED`` are ever stored. Expiry is **derived** from
    ``expires_at`` at verification time and is never a stored status — this
    avoids a background-job contract that flips keys at expiry.
    """

    ACTIVE = "active"
    REVOKED = "revoked"


class MembershipRole(StrEnum):
    """Roles a user may hold inside one organization (spec §4)."""

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class ApplicationRole(StrEnum):
    """Global FeedNow application role carried by a ``User`` (Phase 12).

    Completely separate from :class:`MembershipRole`: membership roles are
    **organization-local** grants resolved per organization, while an
    application role is a single global attribute of the user record. The
    two enums share no code path and neither substitutes for the other —
    ``ADMIN`` appearing in both vocabularies is a naming coincidence, not a
    relationship (spec 12 invariant 1). ``USER`` is the only value any
    writer obtains without naming it; ``ADMIN`` is granted out of band
    (Phase 13 bootstrap), never by login, and API-key principal contexts
    stay roleless (spec 12 invariant 7).
    """

    USER = "user"
    ADMIN = "admin"


class OrganizationType(StrEnum):
    """Kind of organization (spec §4 initial types)."""

    PERSONAL = "personal"
    CUSTOMER = "customer"
    INTERNAL = "internal"


class ApiKeyEnvironment(StrEnum):
    """Credential environment, encoded in the key literal prefix
    ``fn_live_`` / ``fn_test_`` (spec §8)."""

    LIVE = "live"
    TEST = "test"


class IdentityProvider(StrEnum):
    """External identity providers recognized by the domain (spec §4).

    ``cognito`` is the initial provider; the remaining values are reserved by
    the spec for future integrations that must resolve into the same
    user/organization model.
    """

    COGNITO = "cognito"
    SHOPIFY = "shopify"
    GOOGLE = "google"
    MICROSOFT = "microsoft"
    OIDC = "oidc"


__all__ = [
    "ApiKeyEnvironment",
    "ApiKeyStatus",
    "ApplicationRole",
    "IdentityProvider",
    "MembershipRole",
    "MembershipStatus",
    "OrganizationNameStatus",
    "OrganizationStatus",
    "OrganizationType",
    "UserStatus",
]
