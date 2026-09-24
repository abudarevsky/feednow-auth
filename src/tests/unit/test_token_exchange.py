"""Unit tests for the Phase 11 token-exchange client (breakdown task 10).

Pins the :class:`CognitoTokenEndpoint` contract:

- constructor configuration: absolute HTTPS only, no query/fragment,
  non-empty client id, positive timeout;
- the single fixed POST: ``application/x-www-form-urlencoded`` body with
  exactly the five public-PKCE fields (no client secret, no Authorization
  header), the configured URL verbatim, and the timeout handed to the opener;
- response handling: only ``access_token`` is returned; ``id_token`` and
  ``refresh_token`` are discarded without being stored on the client;
- failure classification: every provider-side or incomplete-material
  failure raises ``TokenProviderUnavailableError`` with the exact fixed
  reason — no code, verifier, or token value is ever interpolated;
- hygiene: exception text never carries exchange or token material.

The opener is replaced with a recording fake (the client's only I/O seam),
following the task-2 user-info client's test pattern, so no socket or TLS
fixture is needed; the redirect-rejection policy is pinned on the built
opener because urllib only reaches the handler through a live 3xx.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl

import pytest

from app.auth.cognito import _RejectRedirectHandler
from app.auth.errors import TokenProviderUnavailableError
from app.auth.token_exchange import (
    _MAX_TOKEN_BODY_BYTES,
    MIN_ACCESS_TOKEN_LENGTH,
    CognitoTokenEndpoint,
)

TOKEN_URL = "https://auth.example.eu-central-1.amazoncognito.com/oauth2/token"
CLIENT_ID = "abcdef1234567890abcdef1234"
REDIRECT_URI = "https://api.example.test/oauth/callback"
CODE = "authorization-code-single-use-material"
VERIFIER = "v" * 96  # RFC 7636 verifier (43-128 chars, unreserved charset)
ACCESS_TOKEN = "eyJ" + "a" * 200  # JWT-shaped, comfortably above the floor
ID_TOKEN = "idtok-secret-material-0123456789abcdef"
REFRESH_TOKEN = "refreshtok-secret-material-0123456789abcdef"

#: Removes a member from :func:`_token_body` entirely (distinct from null).
_DROP = object()


class _FakeResponse:
    """Context-manager HTTP response honoring ``read(max_bytes)`` truncation."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, max_bytes: int = -1) -> bytes:
        if max_bytes < 0:
            return self._body
        return self._body[:max_bytes]

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


class _FakeOpener:
    """Records the request/timeout pair, then replays a canned outcome."""

    def __init__(
        self,
        *,
        response: _FakeResponse | None = None,
        error: Exception | None = None,
    ) -> None:
        self._response = response
        self._error = error
        self.calls: list[tuple[urllib.request.Request, float | None]] = []

    def open(
        self,
        request: urllib.request.Request,
        timeout: float | None = None,
    ) -> _FakeResponse:
        self.calls.append((request, timeout))
        if self._error is not None:
            raise self._error
        assert self._response is not None
        return self._response


def _endpoint(opener: _FakeOpener, **kwargs: Any) -> CognitoTokenEndpoint:
    endpoint = CognitoTokenEndpoint(TOKEN_URL, CLIENT_ID, **kwargs)
    endpoint._opener = opener  # the only I/O seam; constructor still validated
    return endpoint


def _token_body(**overrides: Any) -> bytes:
    body: dict[str, Any] = {
        "access_token": ACCESS_TOKEN,
        "id_token": ID_TOKEN,
        "refresh_token": REFRESH_TOKEN,
        "token_type": "Bearer",
        "expires_in": 3600,
    }
    body.update(overrides)
    for key, value in list(body.items()):
        if value is _DROP:
            del body[key]
    return json.dumps(body).encode("utf-8")


def _http_error(code: int = 500) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(TOKEN_URL, code, "server error", None, None)


# -- constructor configuration ------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:9999/oauth2/token",  # cleartext
        "localhost:9999/oauth2/token",  # no scheme
        "/oauth2/token",  # relative
    ],
)
def test_non_https_endpoint_rejected_at_construction(url: str) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        CognitoTokenEndpoint(url, CLIENT_ID)


def test_https_endpoint_without_netloc_rejected() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        CognitoTokenEndpoint("https:///oauth2/token", CLIENT_ID)


@pytest.mark.parametrize("url", [TOKEN_URL + "?code=abc", TOKEN_URL + "#frag"])
def test_query_or_fragment_smuggling_rejected(url: str) -> None:
    with pytest.raises(ValueError, match="query or fragment"):
        CognitoTokenEndpoint(url, CLIENT_ID)


@pytest.mark.parametrize("client_id", ["", None])
def test_empty_client_id_rejected_at_construction(client_id: Any) -> None:
    with pytest.raises(ValueError, match="client_id"):
        CognitoTokenEndpoint(TOKEN_URL, client_id)


@pytest.mark.parametrize("timeout", [0, -1.0])
def test_non_positive_timeout_rejected(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        CognitoTokenEndpoint(TOKEN_URL, CLIENT_ID, timeout_seconds=timeout)


def test_constructed_client_exposes_fixed_configuration() -> None:
    endpoint = CognitoTokenEndpoint(TOKEN_URL, CLIENT_ID)
    assert endpoint.token_endpoint_url == TOKEN_URL
    assert endpoint.client_id == CLIENT_ID


def test_built_opener_rejects_every_redirect() -> None:
    """The task-2 redirect policy is reused: no 3xx target is ever fetched."""
    endpoint = CognitoTokenEndpoint(TOKEN_URL, CLIENT_ID)
    assert any(isinstance(handler, _RejectRedirectHandler) for handler in endpoint._opener.handlers)


# -- happy-path request and response -------------------------------------------


def test_exchange_posts_public_pkce_form_and_returns_only_access_token() -> None:
    opener = _FakeOpener(response=_FakeResponse(_token_body()))
    endpoint = _endpoint(opener, timeout_seconds=2.5)

    token = endpoint.exchange(CODE, REDIRECT_URI, VERIFIER)

    (request, timeout) = opener.calls[0]
    assert len(opener.calls) == 1
    assert request.full_url == TOKEN_URL
    assert request.get_method() == "POST"
    assert request.get_header("Content-type") == "application/x-www-form-urlencoded"
    assert request.get_header("Accept") == "application/json"
    assert request.get_header("Authorization") is None  # public client: no basic auth
    assert timeout == 2.5
    assert parse_qsl(request.data.decode("utf-8"), keep_blank_values=True) == [
        ("grant_type", "authorization_code"),
        ("code", CODE),
        ("redirect_uri", REDIRECT_URI),
        ("client_id", CLIENT_ID),
        ("code_verifier", VERIFIER),
    ]
    assert b"client_secret" not in request.data
    assert token == ACCESS_TOKEN


def test_id_and_refresh_tokens_are_discarded_not_stored() -> None:
    opener = _FakeOpener(response=_FakeResponse(_token_body()))
    endpoint = _endpoint(opener)

    token = endpoint.exchange(CODE, REDIRECT_URI, VERIFIER)

    assert token == ACCESS_TOKEN
    assert ID_TOKEN not in repr(endpoint.__dict__)
    assert REFRESH_TOKEN not in repr(endpoint.__dict__)
    assert endpoint.__dict__["_opener"] is opener  # no response state retained


# -- unusable access_token ------------------------------------------------------


@pytest.mark.parametrize(
    "token",
    [_DROP, None, "", 123, "x" * (MIN_ACCESS_TOKEN_LENGTH - 1)],
    ids=["absent", "null", "empty", "non-string", "short"],
)
def test_missing_or_short_access_token_is_provider_unavailable(token: Any) -> None:
    opener = _FakeOpener(response=_FakeResponse(_token_body(access_token=token)))
    with pytest.raises(TokenProviderUnavailableError) as excinfo:
        _endpoint(opener).exchange(CODE, REDIRECT_URI, VERIFIER)
    assert excinfo.value.reason == "token response did not contain a usable access token"


def test_exactly_minimum_length_token_is_accepted() -> None:
    boundary = "t" * MIN_ACCESS_TOKEN_LENGTH
    opener = _FakeOpener(response=_FakeResponse(_token_body(access_token=boundary)))
    assert _endpoint(opener).exchange(CODE, REDIRECT_URI, VERIFIER) == boundary


# -- pre-wire completeness guard -------------------------------------------------


@pytest.mark.parametrize("field", ["code", "redirect_uri", "code_verifier"])
@pytest.mark.parametrize("bad", ["", None], ids=["empty", "null"])
def test_incomplete_exchange_material_never_reaches_the_wire(field: str, bad: Any) -> None:
    opener = _FakeOpener(response=_FakeResponse(_token_body()))
    arguments: dict[str, Any] = {
        "code": CODE,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": VERIFIER,
    }
    arguments[field] = bad
    with pytest.raises(TokenProviderUnavailableError) as excinfo:
        _endpoint(opener).exchange(**arguments)
    assert excinfo.value.reason == "token exchange request is incomplete"
    assert opener.calls == []


# -- transport / response failures ------------------------------------------------


@pytest.mark.parametrize("code", [302, 400, 401, 500])
def test_any_http_error_status_is_provider_unavailable(code: int) -> None:
    opener = _FakeOpener(error=_http_error(code))
    with pytest.raises(TokenProviderUnavailableError) as excinfo:
        _endpoint(opener).exchange(CODE, REDIRECT_URI, VERIFIER)
    assert excinfo.value.reason == "token endpoint returned an error response"


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.URLError("connection refused"),
        TimeoutError("read timed out"),
        OSError("reset by peer"),
    ],
)
def test_transport_failures_are_provider_unavailable(error: OSError) -> None:
    opener = _FakeOpener(error=error)
    with pytest.raises(TokenProviderUnavailableError) as excinfo:
        _endpoint(opener).exchange(CODE, REDIRECT_URI, VERIFIER)
    assert excinfo.value.reason == "token endpoint could not be reached"


def test_unparseable_body_is_provider_unavailable() -> None:
    opener = _FakeOpener(response=_FakeResponse(b"<html>not json</html>"))
    with pytest.raises(TokenProviderUnavailableError) as excinfo:
        _endpoint(opener).exchange(CODE, REDIRECT_URI, VERIFIER)
    assert excinfo.value.reason == "token response is not a valid JSON document"


def test_json_array_body_is_provider_unavailable() -> None:
    opener = _FakeOpener(response=_FakeResponse(b"[]"))
    with pytest.raises(TokenProviderUnavailableError) as excinfo:
        _endpoint(opener).exchange(CODE, REDIRECT_URI, VERIFIER)
    assert excinfo.value.reason == "token response is not a JSON object"


def test_oversized_body_rejected_before_parsing() -> None:
    body = b"x" * (_MAX_TOKEN_BODY_BYTES + 1)
    opener = _FakeOpener(response=_FakeResponse(body))
    with pytest.raises(TokenProviderUnavailableError) as excinfo:
        _endpoint(opener).exchange(CODE, REDIRECT_URI, VERIFIER)
    assert excinfo.value.reason == "token response is too large"


# -- secrecy hygiene ----------------------------------------------------------------


def test_exception_text_never_carries_code_verifier_or_token_material() -> None:
    failures: list[Callable[[], Any]] = [
        lambda: _endpoint(_FakeOpener(error=_http_error())).exchange(CODE, REDIRECT_URI, VERIFIER),
        lambda: _endpoint(_FakeOpener(error=urllib.error.URLError("refused"))).exchange(
            CODE, REDIRECT_URI, VERIFIER
        ),
        lambda: _endpoint(
            _FakeOpener(response=_FakeResponse(_token_body(access_token=_DROP)))
        ).exchange(CODE, REDIRECT_URI, VERIFIER),
        lambda: _endpoint(
            _FakeOpener(response=_FakeResponse(_token_body(access_token="x" * 8)))
        ).exchange(CODE, REDIRECT_URI, VERIFIER),
        lambda: _endpoint(_FakeOpener(response=_FakeResponse(b"nope"))).exchange(
            CODE, REDIRECT_URI, VERIFIER
        ),
        lambda: _endpoint(_FakeOpener()).exchange("", REDIRECT_URI, VERIFIER),
    ]
    for call in failures:
        with pytest.raises(TokenProviderUnavailableError) as excinfo:
            call()
        text = str(excinfo.value)
        assert CODE not in text
        assert VERIFIER not in text
        assert ACCESS_TOKEN not in text
        assert ID_TOKEN not in text
        assert REFRESH_TOKEN not in text
        assert CLIENT_ID not in text
