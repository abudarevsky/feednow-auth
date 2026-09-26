"""Provider-neutral domain entities and value types.

Phase 01 contract surface (frozen for downstream phases):

- Conventions live in :mod:`app.models.ids`, :mod:`app.models.timestamps`,
  :mod:`app.models.pagination`, :mod:`app.models.errors` (import them from
  those modules; they are not re-exported here).
- This package re-exports the enum sets and entity models: identity
  entities (spec §4) plus the credential, audit, and authorization
  entities (:mod:`app.models.api_key`, :mod:`app.models.audit_event`,
  :mod:`app.models.authorization_context`).
- Phase 11 adds the additive session surface: :class:`OAuthLoginState` and
  :class:`AppSession` from :mod:`app.models.session`.
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
    OrganizationNameStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.external_identity import ExternalIdentity, ProviderTenant
from app.models.membership import Membership
from app.models.organization import Organization, OrganizationName, OrganizationSlug
from app.models.session import (
    AppSession,
    CodeVerifier,
    OAuthLoginState,
    ReturnUrl,
    SessionId,
    StateId,
)
from app.models.user import Email, User

__all__ = [
    "ActorType",
    "ApiKey",
    "ApiKeyEnvironment",
    "ApiKeyName",
    "ApiKeyStatus",
    "AppSession",
    "AuditAction",
    "AuditEvent",
    "AuditMetadata",
    "AuditTargetId",
    "AuditTargetType",
    "AuthorizationContext",
    "CodeVerifier",
    "Email",
    "ExternalIdentity",
    "IdentityProvider",
    "KeyId",
    "KeyPrefix",
    "Membership",
    "MembershipRole",
    "MembershipStatus",
    "OAuthLoginState",
    "Organization",
    "OrganizationName",
    "OrganizationNameStatus",
    "OrganizationSlug",
    "OrganizationStatus",
    "OrganizationType",
    "ProviderTenant",
    "ReturnUrl",
    "Scope",
    "SecretHash",
    "SessionId",
    "StateId",
    "User",
    "UserStatus",
]
