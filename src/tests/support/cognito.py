"""Cognito-shaped token fixtures: RSA keygen, signer, and a counting JWKS server.

Per the Phase 03 test-strategy decision, this module provides exactly the
sanctioned fixtures — no live Cognito pool, ever:

- :func:`generate_test_key` — throwaway RSA-2048 keypair bound to a ``kid``.
- :func:`sign_token` — RS256 signer with caller-owned claim overrides so
  negative tests can mint expired/wrong-issuer/``token_use=id`` tokens.
- :func:`jwks_payload` — the ``{"keys": [...]}`` document a Cognito-style
  domain would publish.
- :class:`JwksTestServer` — stdlib ``ThreadingHTTPServer`` on
  ``127.0.0.1:0`` serving one key set per issuer path segment and counting
  requests, which is how the caching and cross-issuer proofs work.

Issuer URLs are ``http://127.0.0.1:{port}/{segment}`` so the source-derived
JWKS URL ``{iss}/.well-known/jwks.json`` maps onto
``/{segment}/.well-known/jwks.json`` on this server.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import Any, Self

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jwt.algorithms import RSAAlgorithm

#: Loopback-only host; the server never binds a routable interface.
TEST_HOST = "127.0.0.1"

#: OIDC-standard suffix ``CognitoJwksSource`` appends to every issuer.
JWKS_SUFFIX = "/.well-known/jwks.json"

RSA_KEY_SIZE = 2048


@dataclass(frozen=True)
class TestKey:
    """One RSA-2048 test keypair with the ``kid`` it is published under."""

    __test__ = False  # dataclass, not a pytest test class

    kid: str
    private_key: RSAPrivateKey

    @property
    def jwk(self) -> dict[str, Any]:
        """The **public** half as a signing JWK (``use``/``alg`` pinned like Cognito's).

        Built from ``private_key.public_key()`` on purpose: PyJWT's
        ``to_jwk`` on a private key object would serialize ``d``/``p``/``q``
        into the published document — private material must never leave the
        fixture, mirroring the project no-secrets rule.
        """
        jwk: dict[str, Any] = json.loads(RSAAlgorithm.to_jwk(self.private_key.public_key()))
        jwk.pop("key_ops", None)  # Cognito-shaped members only
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return jwk


def generate_test_key(kid: str = "test-kid") -> TestKey:
    """Generate a throwaway RSA-2048 keypair (test entropy, never product)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    return TestKey(kid=kid, private_key=private_key)


def sign_token(
    claims: Mapping[str, Any],
    *,
    kid: str | None,
    key: TestKey | bytes | str,
    alg: str = "RS256",
) -> str:
    """Sign ``claims`` verbatim, publishing ``kid`` in the JWT header.

    Every claim value is caller-owned (no defaults), so negative tests fully
    control expiry, issuer, ``token_use``, etc. ``key`` is a :class:`TestKey`
    for RSA flows or raw ``bytes``/``str`` material for algorithm-confusion
    forgeries; ``alg`` is overridable (``"none"`` ignores ``key`` entirely,
    as PyJWT requires). ``kid=None`` omits the ``kid`` header member
    entirely — distinct from an empty-string ``kid``.
    """
    if alg == "none":
        signing_key: Any = None
    elif isinstance(key, TestKey):
        signing_key = key.private_key
    else:
        signing_key = key
    headers = None if kid is None else {"kid": kid}
    return jwt.encode(dict(claims), signing_key, algorithm=alg, headers=headers)


def jwks_payload(keys: Sequence[TestKey]) -> dict[str, Any]:
    """Build the JWK Set document publishing the public halves of ``keys``."""
    return {"keys": [key.jwk for key in keys]}


class _JwksHTTPServer(ThreadingHTTPServer):
    """Server with a back-reference to the fixture wrapper and per-path counts."""

    daemon_threads = True
    owner: JwksTestServer  # set immediately after construction


class _JwksRequestHandler(BaseHTTPRequestHandler):
    """Serves registered JWKS paths; everything else is a 404. Both counted."""

    server: _JwksHTTPServer

    def do_GET(self) -> None:  # stdlib handler naming (do_GET)
        payload = self.server.owner.handle_get(self.path)
        if payload is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Silence the default stderr access log (pytest output stays clean)."""


class JwksTestServer:
    """Counting, threaded, loopback-only JWKS test server (fixture, not product).

    Usage::

        with JwksTestServer({"pool-a": [key_a], "pool-b": [key_b]}) as server:
            source = CognitoJwksSource([server.issuer("pool-a"), server.issuer("pool-b")])
            ...
            assert server.request_count == 1  # caching proof
    """

    def __init__(self, key_sets: Mapping[str, Sequence[TestKey]]) -> None:
        self._payloads = {
            self._path(segment): jwks_payload(keys) for segment, keys in key_sets.items()
        }
        self._lock = threading.Lock()
        self._total_requests = 0
        self._path_counts: dict[str, int] = {}
        self._server = _JwksHTTPServer((TEST_HOST, 0), _JwksRequestHandler)
        self._server.owner = self
        self._thread: threading.Thread | None = None
        self._stopped = False

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    def start(self) -> None:
        """Bind is done in the constructor; this starts the serving thread."""
        if self._thread is not None:
            raise RuntimeError("JwksTestServer already started")
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="jwks-test-server", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop serving and close the socket; idempotent.

        After ``stop()`` the port is closed, so the next client fetch gets a
        connection error — this is the "server down" failure proof.
        """
        if self._stopped:
            return
        self._stopped = True
        if self._thread is not None:
            self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    # -- addresses ---------------------------------------------------------

    @property
    def port(self) -> int:
        """The OS-assigned loopback port (available before ``start()``)."""
        address = self._server.server_address
        return int(address[1])

    def issuer(self, segment: str) -> str:
        """The issuer URL whose derived JWKS path this server serves."""
        return f"http://{TEST_HOST}:{self.port}/{segment}"

    def jwks_url(self, segment: str) -> str:
        """The exact URL ``CognitoJwksSource`` will fetch for ``issuer(segment)``."""
        return f"{self.issuer(segment)}{JWKS_SUFFIX}"

    # -- request accounting -------------------------------------------------

    @property
    def request_count(self) -> int:
        """Total GETs served (hits and 404s) since construction."""
        with self._lock:
            return self._total_requests

    def requests_for(self, segment: str) -> int:
        """GETs served for one issuer segment's JWKS path (404s included)."""
        with self._lock:
            return self._path_counts.get(self._path(segment), 0)

    def handle_get(self, path: str) -> dict[str, Any] | None:
        """Count ``path`` and return its JWKS payload, or None for unknown paths."""
        with self._lock:
            self._total_requests += 1
            self._path_counts[path] = self._path_counts.get(path, 0) + 1
            return self._payloads.get(path)

    @staticmethod
    def _path(segment: str) -> str:
        return f"/{segment}{JWKS_SUFFIX}"


__all__ = [
    "JWKS_SUFFIX",
    "RSA_KEY_SIZE",
    "TEST_HOST",
    "JwksTestServer",
    "TestKey",
    "generate_test_key",
    "jwks_payload",
    "sign_token",
]
