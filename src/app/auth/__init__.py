"""JWT/API-key authentication and authorization resolution.

identity tasks 2—3 publish the auth-boundary contracts re-exported below:
the token-error hierarchy and issuer-bound :class:`JwksSource` (implementation) and
the access-token verifier with its frozen claims and the
:class:`AccessTokenVerifier` handoff protocol (implementation). organization adds
the shared organization-access dependency (member/admin minimums). API-key adds the API-key credential primitives (format, parse, peppered
hash) and the :class:`PepperSource` abstraction; implementation adds the verification
pipeline (:func:`verify_api_key`, its uniform :class:`ApiKeyAuthenticationError`,
and :func:`build_api_key_context`/ :func:`key_has_scope`); implementation adds the
principal dispatch (:class:`Principal`, :func:`build_current_principal`) and
the organization-access API-key branch (the ``pepper_source``-wired
factories, :class:`PrincipalAccess`, and
:func:`build_organization_scope_dependency`).

Current behavior and invariants: ``docs/authentication.md``."""

from app.auth.api_key_auth import (
    ApiKeyAuthenticationError,
    VerifiedApiKey,
    build_api_key_context,
    key_has_scope,
    verify_api_key,
)
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
from app.auth.dependencies import build_current_principal
from app.auth.errors import (
    TokenProviderUnavailableError,
    TokenValidationError,
    UnknownKeyIdError,
)
from app.auth.jwks import JWKS_PATH, CognitoJwksSource, JwksSource
from app.auth.organization_access import (
    OrganizationAccess,
    PrincipalAccess,
    build_organization_admin_dependency,
    build_organization_member_dependency,
    build_organization_scope_dependency,
)
from app.auth.pepper import PepperSource, StaticPepper
from app.auth.principal import Principal

__all__ = [
    "JWKS_PATH",
    "AccessTokenVerifier",
    "ApiKeyAuthenticationError",
    "ApiKeyCredentialFormatError",
    "CognitoAccessTokenVerifier",
    "CognitoClaims",
    "CognitoJwksSource",
    "JwksSource",
    "OrganizationAccess",
    "ParsedCredential",
    "PepperSource",
    "Principal",
    "PrincipalAccess",
    "StaticPepper",
    "TokenProviderUnavailableError",
    "TokenValidationError",
    "UnknownKeyIdError",
    "VerifiedApiKey",
    "build_api_key_context",
    "build_current_principal",
    "build_literal",
    "build_organization_admin_dependency",
    "build_organization_member_dependency",
    "build_organization_scope_dependency",
    "dummy_secret_matches",
    "generate_key_id",
    "generate_secret",
    "hash_secret",
    "key_has_scope",
    "parse_literal",
    "secret_matches",
    "verify_api_key",
]
