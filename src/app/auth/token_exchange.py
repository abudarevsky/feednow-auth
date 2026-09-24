"""Authorization-code + PKCE token-exchange client (Phase 11 task 10).

Exchanges a Cognito Hosted UI authorization code for an access token over
the RFC 6749 / RFC 7636 ``POST /oauth2/token`` form flow. The client is the
*public* PKCE variant matching the Phase 07 app client: the form carries
``code_verifier`` and **no client secret is ever sent, stored, or accepted**
by this module (AGENTS.md no-secrets rule).

Contract (breakdown task 10):

- :class:`CognitoTokenEndpoint` pins approved configuration at
  construction: absolute HTTPS token endpoint (no query/fragment, so no
  per-call URL selection or parameter smuggling) and a non-empty
  ``client_id``. The same redirect-rejection policy as the task-2
  user-info client is reused (:class:`app.auth.cognito._RejectRedirectHandler`),
  because following a redirect off the token endpoint could move the
  code/verifier pair to another origin.
- :meth:`CognitoTokenEndpoint.exchange` issues exactly one
  ``application/x-www-form-urlencoded`` POST with the fixed five fields
  (``grant_type=authorization_code``, ``code``, ``redirect_uri``,
  ``client_id``, ``code_verifier``), parses the JSON object response, and
  returns **only** ``access_token``. ``id_token`` and ``refresh_token`` are
  discarded without storing or echoing them — the application reads the
  verified user-info profile instead (Phase 11 decision).
- Every provider-side failure — transport error, timeout, non-2xx
  (redirects included), oversized or unparseable body, and a
  missing/short/non-string ``access_token`` — raises
  :class:`~app.auth.errors.TokenProviderUnavailableError` (503-mapped by
  the task-12 callback route) with a **fixed, safe reason** that never
  interpolates the code, verifier, or any token material. A pre-wire
  completeness guard keeps empty caller-supplied exchange material from
  ever leaving the process, using the same fixed-reason vocabulary.

Like the rest of the auth boundary, this module imports no logging; the
authorization code is a single-use bearer credential and the verifier is
the PKCE secret, so neither may appear in exception text or logs.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any, Final
from urllib.parse import urlencode, urlparse

from app.auth.cognito import _RejectRedirectHandler
from app.auth.errors import TokenProviderUnavailableError

#: Response body cap, mirroring the user-info client's bound: a token
#: response is a small JSON document, and anything larger is treated as a
#: provider fault before it is ever parsed.
_MAX_TOKEN_BODY_BYTES: Final = 65_536

#: Lower bound for a usable ``access_token``. Cognito access tokens are
#: RS256 JWTs (hundreds of characters); anything shorter is a truncated or
#: malformed provider response, never a real token, so it fails closed.
MIN_ACCESS_TOKEN_LENGTH: Final = 32

#: OIDC-standard grant type for the authorization-code exchange.
_GRANT_TYPE: Final = "authorization_code"


class CognitoTokenEndpoint:
    """Exchanges authorization codes for access tokens at a fixed HTTPS endpoint.

    Constructed once per app from approved configuration; holds no
    per-request state, so it is safe to share across requests. The opener
    is built once with :class:`_RejectRedirectHandler` and reused (urllib
    openers are thread-safe for independent requests); timeouts are
    enforced per request.
    """

    def __init__(
        self,
        token_endpoint_url: str,
        client_id: str,
        timeout_seconds: float = 5.0,
    ) -> None:
        self._token_endpoint_url = self._validate_token_endpoint_url(token_endpoint_url)
        if not isinstance(client_id, str) or not client_id:
            raise ValueError("client_id must be a non-empty string")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._client_id = client_id
        self._timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(_RejectRedirectHandler())

    @property
    def token_endpoint_url(self) -> str:
        """The fixed HTTPS token endpoint this client will POST to."""
        return self._token_endpoint_url

    @property
    def client_id(self) -> str:
        """The public PKCE client id sent in every exchange form."""
        return self._client_id

    def exchange(self, code: str, redirect_uri: str, code_verifier: str) -> str:
        """Redeem ``code`` (with its PKCE ``code_verifier``) for an access token.

        ``redirect_uri`` must be the exact value used at authorization time
        (RFC 6749 §4.1.3 binds the code to it). Returns only the provider's
        ``access_token`` string.

        :raises TokenProviderUnavailableError: incomplete exchange material
            (never sent), transport failure, timeout, any non-2xx
            (redirects included), an over-cap or unparseable body, or a
            missing/short/non-string ``access_token``. Fixed safe reasons
            only — no code, verifier, or token material.
        """
        for material in (code, redirect_uri, code_verifier):
            if not isinstance(material, str) or not material:
                raise TokenProviderUnavailableError("token exchange request is incomplete")
        form = urlencode(
            {
                "grant_type": _GRANT_TYPE,
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": self._client_id,
                "code_verifier": code_verifier,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self._token_endpoint_url,
            data=form,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )
        # HTTPError is a URLError subclass and URLError an OSError subclass:
        # the order below keeps "endpoint answered badly" distinct from
        # "endpoint unreachable" (which covers DNS, TLS, and read timeouts),
        # mirroring the user-info client's classification.
        try:
            with self._opener.open(request, timeout=self._timeout_seconds) as response:
                body: bytes = response.read(_MAX_TOKEN_BODY_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise TokenProviderUnavailableError(
                "token endpoint returned an error response"
            ) from exc
        except OSError as exc:
            raise TokenProviderUnavailableError("token endpoint could not be reached") from exc
        if len(body) > _MAX_TOKEN_BODY_BYTES:
            raise TokenProviderUnavailableError("token response is too large")
        return self._extract_access_token(self._parse_json_object(body))

    @staticmethod
    def _validate_token_endpoint_url(token_endpoint_url: str) -> str:
        """Pin approved configuration: absolute HTTPS, no query or fragment.

        A per-request URL selection point or an http:// endpoint would let
        the code and verifier travel in cleartext or to an unapproved host;
        a query/fragment would smuggle parameters into the fixed POST.
        """
        parsed = urlparse(token_endpoint_url)
        if parsed.scheme.lower() != "https" or not parsed.netloc:
            raise ValueError("token_endpoint_url must be an absolute HTTPS URL")
        if parsed.query or parsed.fragment:
            raise ValueError("token_endpoint_url must not contain a query or fragment")
        return token_endpoint_url

    @staticmethod
    def _parse_json_object(body: bytes) -> Mapping[str, Any]:
        """Decode the response body fail-closed; parse failures are provider faults."""
        try:
            payload = json.loads(body)
        except ValueError as exc:  # json.JSONDecodeError subclasses ValueError
            raise TokenProviderUnavailableError(
                "token response is not a valid JSON document"
            ) from exc
        if not isinstance(payload, dict):
            raise TokenProviderUnavailableError("token response is not a JSON object")
        return payload

    @staticmethod
    def _extract_access_token(payload: Mapping[str, Any]) -> str:
        """Return the sole ``access_token`` member; every other member is discarded.

        ``id_token`` and ``refresh_token`` are deliberately never read —
        they are dropped with the payload itself, so no long-lived provider
        material can be echoed through this seam. A missing, non-string, or
        implausibly short access token is a provider contract violation
        (503-mapped), not a caller rejection.
        """
        token = payload.get("access_token")
        if not isinstance(token, str) or len(token) < MIN_ACCESS_TOKEN_LENGTH:
            raise TokenProviderUnavailableError(
                "token response did not contain a usable access token"
            )
        return token


__all__ = ["MIN_ACCESS_TOKEN_LENGTH", "CognitoTokenEndpoint"]
