"""JWT/API-key authentication and authorization resolution.

Phase 03 tasks 2—3 publish the auth-boundary contracts re-exported below:
the token-error hierarchy and issuer-bound :class:`JwksSource` (task 2) and
the access-token verifier with its frozen claims and the
:class:`AccessTokenVerifier` handoff protocol (task 3). API-key credential
logic joins this package in Phase 05.
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

__all__ = [
    "JWKS_PATH",
    "AccessTokenVerifier",
    "CognitoAccessTokenVerifier",
    "CognitoClaims",
    "CognitoJwksSource",
    "JwksSource",
    "TokenProviderUnavailableError",
    "TokenValidationError",
    "UnknownKeyIdError",
]
