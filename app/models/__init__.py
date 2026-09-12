"""Provider-neutral domain entities and value types.

Phase 01 contract surface (frozen for downstream phases):

- Conventions live in :mod:`app.models.ids`, :mod:`app.models.timestamps`,
  :mod:`app.models.pagination`, :mod:`app.models.errors` (import them from
  those modules; they are not re-exported here).
- This package re-exports the enum sets and entity models. Credential,
  audit, and authorization entities are added by the next task.
"""

from app.models.enums import (
    ApiKeyEnvironment,
    ApiKeyStatus,
    IdentityProvider,
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.external_identity import ExternalIdentity, ProviderTenant
from app.models.membership import Membership
from app.models.organization import Organization, OrganizationName, OrganizationSlug
from app.models.user import Email, User

__all__ = [
    "ApiKeyEnvironment",
    "ApiKeyStatus",
    "Email",
    "ExternalIdentity",
    "IdentityProvider",
    "Membership",
    "MembershipRole",
    "MembershipStatus",
    "Organization",
    "OrganizationName",
    "OrganizationSlug",
    "OrganizationStatus",
    "OrganizationType",
    "ProviderTenant",
    "User",
    "UserStatus",
]
