"""Issuer-bound JWKS retrieval for Cognito access tokens (Phase 03 task 2).

Implements planner decision "JWKS" from the Phase 03 breakdown:

- The key-set URL is derived as ``{iss}/.well-known/jwks.json`` — Cognito's
  OIDC-standard discovery path. The issuer string is only ever taken from the
  configured allowlist (exact set membership), so no attacker-controlled
  token claim can steer a fetch URL (SSRF boundary; the pinned PyJWT floor
  also rejects non-http(s) schemes inside ``PyJWKClient``).
- One ``jwt.PyJWKClient(url, cache_keys=True)`` is built **lazily per allowed
  issuer** and held for the source's lifetime. ``cache_keys=True`` enables
  PyJWT's per-key LRU so repeat lookups of a known ``kid`` never re-fetch.
- Key rotation rides on PyJWKClient's refetch-on-unknown-kid behavior. The
  ``cooldown_duration`` parameter is deliberately **not** passed: it exists
  only from 2.14 while the dependency floor is 2.13, so passing it would
  break the minimum supported version. On the resolved 2.14 its default
  30-second cooldown gates the rotation refetch (an unknown kid within 30s
  of a successful fetch raises ``UnknownKeyIdError`` without refetching);
  proactive TTL refresh, immediate-rotation tuning, and fetch rate-limiting
  are deferred to Phase 08.
- Failure classification (PyJWT's own hierarchy makes this message-free):
  ``PyJWKClientConnectionError`` (HTTP failure of any kind, including 4xx/5xx
  responses) → :class:`TokenProviderUnavailableError`; a plain
  ``PyJWKClientError`` (no key matched the ``kid``) →
  :class:`UnknownKeyIdError`. A degenerate endpoint that returns valid JSON
  but no usable keys therefore surfaces as ``UnknownKeyIdError`` — fail-closed
  as an invalid token, which is acceptable until Phase 08 hardening.

The :class:`JwksSource` protocol is the **published handoff interface**
(task 7). It is issuer-bound — ``signing_key(issuer, kid)`` — because with a
plural allowlist a kid-only lookup would force cross-issuer scanning, and two
issuers may legitimately reuse a kid string; changing that shape later would
be a breaking change for Phases 06/07.

No verifier logic lives here — claim validation and decoding arrive with the
task-3 :mod:`app.auth.cognito` module.
"""

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
    """Issuer-bound signing-key lookup — the Phase 03 published interface.

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
