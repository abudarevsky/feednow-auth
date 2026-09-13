"""JWT/API-key authentication and authorization resolution.

Phase 03 task 2 publishes the auth-boundary contracts re-exported below:
the token-error hierarchy and the issuer-bound :class:`JwksSource`. The
access-token verifier joins this package in task 3, and API-key credential
logic in Phase 05.
"""

from app.auth.errors import (
    TokenProviderUnavailableError,
    TokenValidationError,
    UnknownKeyIdError,
)
from app.auth.jwks import JWKS_PATH, CognitoJwksSource, JwksSource

__all__ = [
    "JWKS_PATH",
    "CognitoJwksSource",
    "JwksSource",
    "TokenProviderUnavailableError",
    "TokenValidationError",
    "UnknownKeyIdError",
]
