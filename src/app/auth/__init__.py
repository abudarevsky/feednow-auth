"""JWT/API-key authentication and authorization resolution.

Phase 03 tasks 2—3 publish the auth-boundary contracts re-exported below:
the token-error hierarchy and issuer-bound :class:`JwksSource` (task 2) and
the access-token verifier with its frozen claims and the
:class:`AccessTokenVerifier` handoff protocol (task 3). Phase 04 task 3 adds
the shared organization-access dependency (member/admin minimums). Phase 05
task 1 adds the API-key credential primitives (format, parse, peppered
hash) and the :class:`PepperSource` abstraction; the verification pipeline
and principal dispatch join this package in later Phase 05 tasks.
"""

from app.auth.cognito import (
    AccessTokenVerifier,
    CognitoAccessTokenVerifier,
    CognitoClaims,
)
from app.auth.credentials import (
    ApiKeyCredentialFormatError,
    ParsedCredential,
    build_literal,
    dummy_secret_matches,
    generate_key_id,
    generate_secret,
    hash_secret,
    parse_literal,
    secret_matches,
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
from app.auth.pepper import PepperSource, StaticPepper

__all__ = [
    "JWKS_PATH",
    "AccessTokenVerifier",
    "ApiKeyCredentialFormatError",
    "CognitoAccessTokenVerifier",
    "CognitoClaims",
    "CognitoJwksSource",
    "JwksSource",
    "OrganizationAccess",
    "ParsedCredential",
    "PepperSource",
    "StaticPepper",
    "TokenProviderUnavailableError",
    "TokenValidationError",
    "UnknownKeyIdError",
    "build_literal",
    "build_organization_admin_dependency",
    "build_organization_member_dependency",
    "dummy_secret_matches",
    "generate_key_id",
    "generate_secret",
    "hash_secret",
    "parse_literal",
    "secret_matches",
]
