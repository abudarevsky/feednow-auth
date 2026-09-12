"""Provider-neutral domain entities and value types.

Phase 01 contract surface (frozen for downstream phases):

- Conventions live in :mod:`app.models.ids`, :mod:`app.models.timestamps`,
  :mod:`app.models.pagination`, :mod:`app.models.errors` (import them from
  those modules; they are not re-exported here).
- This package re-exports the enum sets and entity models: identity
  entities (spec §4) plus the credential, audit, and authorization
  entities (:mod:`app.models.api_key`, :mod:`app.models.audit_event`,
  :mod:`app.models.authorization_context`).
"""

from app.models.api_key import (
    ApiKey,
    ApiKeyName,
    KeyId,
    KeyPrefix,
    Scope,
    SecretHash,
)
from app.models.audit_event import (
    AuditAction,
    AuditEvent,
    AuditMetadata,
    AuditTargetId,
    AuditTargetType,
)
from app.models.authorization_context import ActorType, AuthorizationContext
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
    "ActorType",
    "ApiKey",
    "ApiKeyEnvironment",
    "ApiKeyName",
    "ApiKeyStatus",
    "AuditAction",
    "AuditEvent",
    "AuditMetadata",
    "AuditTargetId",
    "AuditTargetType",
    "AuthorizationContext",
    "Email",
    "ExternalIdentity",
    "IdentityProvider",
    "KeyId",
    "KeyPrefix",
    "Membership",
    "MembershipRole",
    "MembershipStatus",
    "Organization",
    "OrganizationName",
    "OrganizationSlug",
    "OrganizationStatus",
    "OrganizationType",
    "ProviderTenant",
    "Scope",
    "SecretHash",
    "User",
    "UserStatus",
]
