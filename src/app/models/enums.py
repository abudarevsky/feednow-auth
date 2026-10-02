"""Domain enumerations for the FeedNow identity model.

Values are **pinned** by the initial design notes (Planner decisions): the contract
names these concepts but does not enumerate them, storage stores them as
strings, and API-key branches on them. Renaming or adding a value is a
contract change and requires a contract revision.

All enums are :class:`~enum.StrEnum`s, so they validate from and serialize to
their exact lowercase string values (JSON round-trips are plain strings;
unknown strings are rejected by Pydantic).

Current behavior and invariants: ``docs/architecture.md``."""

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
    """Roles a user may hold inside one organization (domain model contract)."""

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class ApplicationRole(StrEnum):
    """Global FeedNow application role carried by a ``User`` (application-role).

    Completely separate from :class:`MembershipRole`: membership roles are
    **organization-local** grants resolved per organization, while an
    application role is a single global attribute of the user record. The
    two enums share no code path and neither substitutes for the other —
    ``ADMIN`` appearing in both vocabularies is a naming coincidence, not a
    relationship (contract 12 invariant 1). ``USER`` is the only value any
    writer obtains without naming it; ``ADMIN`` is granted out of band
    (admin bootstrap), never by login, and API-key principal contexts
    stay roleless (contract 12 invariant 7).
    """

    USER = "user"
    ADMIN = "admin"


class OrganizationType(StrEnum):
    """Kind of organization (domain model contract initial types)."""

    PERSONAL = "personal"
    CUSTOMER = "customer"
    INTERNAL = "internal"


class ApiKeyEnvironment(StrEnum):
    """Credential environment, encoded in the key literal prefix
    ``fn_live_`` / ``fn_test_`` (credential contract)."""

    LIVE = "live"
    TEST = "test"


class IdentityProvider(StrEnum):
    """External identity providers recognized by the domain (domain model contract).

    ``cognito`` is the initial provider; the remaining values are reserved by
    the contract for future integrations that must resolve into the same
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
