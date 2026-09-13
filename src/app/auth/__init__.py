"""JWT/API-key authentication and authorization resolution.

Phase 03 tasks 2—3 publish the auth-boundary contracts re-exported below:
the token-error hierarchy and issuer-bound :class:`JwksSource` (task 2) and
the access-token verifier with its frozen claims and the
:class:`AccessTokenVerifier` handoff protocol (task 3). Phase 04 task 3 adds
the shared organization-access dependency (member/admin minimums). API-key
credential logic joins this package in Phase 05.
"""

from app.auth.cognito import (
    AccessTokenVerifier,
    CognitoAccessTokenVerifier,
    CognitoClaims,
)
from app.auth.errors import (
    TokenProviderUnavailableError,
    TokenValidationError,
    UnknownKeyIdError,
)
from app.auth.jwks import JWKS_PATH, CognitoJwksSource, JwksSource
from app.auth.organization_access import (
    OrganizationAccess,
    build_organization_admin_dependency,
    build_organization_member_dependency,
)

__all__ = [
    "JWKS_PATH",
    "AccessTokenVerifier",
    "CognitoAccessTokenVerifier",
    "CognitoClaims",
    "CognitoJwksSource",
    "JwksSource",
    "OrganizationAccess",
    "TokenProviderUnavailableError",
    "TokenValidationError",
    "UnknownKeyIdError",
    "build_organization_admin_dependency",
    "build_organization_member_dependency",
]
