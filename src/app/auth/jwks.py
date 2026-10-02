"""Issuer-bound JWKS retrieval for Cognito access tokens. A key identifier is resolved only from its configured issuer, with refresh on an unknown key identifier.

Current behavior and invariants: ``docs/authentication.md``."""

from __future__ import annotations

import threading
from collections.abc import Iterable
from typing import Final, Protocol, runtime_checkable
from urllib.parse import urlparse

from jwt import PyJWK, PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError

from app.auth.errors import TokenProviderUnavailableError, TokenValidationError, UnknownKeyIdError

#: Path Cognito (and OIDC discovery) publishes the signing key set at.
JWKS_PATH: Final = "/.well-known/jwks.json"


@runtime_checkable
class JwksSource(Protocol):
    """Issuer-bound signing-key lookup — the identity published interface.

    Implementations resolve a key **only** from the key set published by
    ``issuer``; a ``kid`` that exists under a different issuer must never be
    returned (cross-issuer isolation, planner decision "JWKS").
    """

    def signing_key(self, issuer: str, kid: str) -> PyJWK: ...


class CognitoJwksSource:
    """Fetches and caches signing keys from Cognito-domain JWKS endpoints.

    Constructed with the exact issuer allowlist (the same set the verifier
    checks ``iss`` against — kept as an independent copy so this class never
    trusts a caller-supplied issuer at fetch time). Clients are built lazily:
    a configured-but-never-used issuer costs no connection or memory.
    """

    def __init__(self, allowed_issuers: Iterable[str]) -> None:
        issuers = frozenset(allowed_issuers)
        if not issuers:
            raise ValueError("allowed_issuers must contain at least one issuer")
        for issuer in sorted(issuers):  # deterministic failure for the first offender
            self._validate_issuer(issuer)
        self._allowed_issuers: Final = issuers
        self._clients: dict[str, PyJWKClient] = {}
        self._lock = threading.Lock()

    @property
    def allowed_issuers(self) -> frozenset[str]:
        """The configured exact-match issuer allowlist."""
        return self._allowed_issuers

    def signing_key(self, issuer: str, kid: str) -> PyJWK:
        """Return the signing key for ``kid`` from ``issuer``'s key set only.

        :raises TokenValidationError: ``issuer`` is not in the allowlist
            (defense in depth behind the verifier's own ``iss`` check).
        :raises UnknownKeyIdError: the allowed issuer published no key for
            ``kid`` (after PyJWKClient's rotation-driven refetch).
        :raises TokenProviderUnavailableError: the issuer's JWKS endpoint
            could not be fetched.
        """
        if issuer not in self._allowed_issuers:
            raise TokenValidationError("token issuer is not in the allowlist")
        client = self._client_for(issuer)
        try:
            return client.get_signing_key(kid)
        except PyJWKClientConnectionError as exc:
            raise TokenProviderUnavailableError() from exc
        except PyJWKClientError as exc:
            raise UnknownKeyIdError() from exc

    def _client_for(self, issuer: str) -> PyJWKClient:
        """Return (building on first use) the one client bound to ``issuer``."""
        client = self._clients.get(issuer)
        if client is not None:
            return client
        with self._lock:
            client = self._clients.get(issuer)
            if client is None:
                client = PyJWKClient(f"{issuer}{JWKS_PATH}", cache_keys=True)
                self._clients[issuer] = client
            return client

    @staticmethod
    def _validate_issuer(issuer: str) -> None:
        """Fail fast on issuer configuration that could not yield a safe URL.

        The allowlist is the SSRF boundary, so entries must be absolute
        http(s) URLs shaped like Cognito issuers (``https://host/{region}/{pool}``):
        a trailing slash would derive ``//.well-known/...`` and query/fragment
        parts would be carried into the derived URL.
        """
        parsed = urlparse(issuer)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"allowed issuer must be an absolute http(s) URL, got {issuer!r}")
        if issuer.endswith("/") or parsed.query or parsed.fragment:
            raise ValueError(
                f"allowed issuer must have no trailing slash, query, or fragment: {issuer!r}"
            )


__all__ = ["JWKS_PATH", "CognitoJwksSource", "JwksSource"]
