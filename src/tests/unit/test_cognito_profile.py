"""Unit tests for the Phase 11 profile seam added to ``app.auth.cognito``.

Covers the frozen :class:`CognitoProfile` value object, the provisioning
gate :func:`require_provisioning_profile` (task-1 rules), and the narrow
:class:`CognitoUserInfoClient` (task-2 rules):

- constructor configuration: absolute HTTPS only, no query/fragment,
  positive timeout;
- the single fixed GET: ``Authorization: Bearer`` + ``Accept`` headers, the
  configured URL verbatim, and the timeout handed to the opener;
- profile parsing: ``name`` → ``display_name`` (absent/null/empty → None),
  optional ``email``, strict boolean ``email_verified``, every string bound;
- subject pinning: a profile for any other ``sub`` is rejected;
- failure classification: shape/subject → ``TokenValidationError``,
  transport/non-2xx/redirect/oversized/unparseable → ``TokenProviderUnavailableError``,
  each with the exact fixed reason;
- hygiene: no token, email, or subject material in any exception text.

The opener is replaced with a recording fake (the client's only I/O seam),
so no socket or TLS fixture is needed; the redirect-rejection handler is
pinned directly because urllib only reaches it through a live 3xx.
"""

from __future__ import annotations

import dataclasses
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

import pytest

from app.auth.cognito import (
    _MAX_PROFILE_BODY_BYTES,
    CognitoProfile,
    CognitoUserInfoClient,
    ProfileSource,
    _RejectRedirectHandler,
    require_provisioning_profile,
)
from app.auth.errors import TokenProviderUnavailableError, TokenValidationError

USERINFO_URL = "https://auth.example.eu-central-1.amazoncognito.com/oauth2/userInfo"
SUBJECT = "11111111-2222-3333-4444-555555555555"
ACCESS_TOKEN = "superscretaccesstoken-material"
EMAIL = "victim@example.com"

#: Removes a member from :func:`_profile_body` entirely (distinct from null).
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


def _client(opener: _FakeOpener, **kwargs: Any) -> CognitoUserInfoClient:
    client = CognitoUserInfoClient(USERINFO_URL, **kwargs)
    client._opener = opener  # the only I/O seam; constructor still validated
    return client


def _profile_body(**overrides: Any) -> bytes:
    body: dict[str, Any] = {
        "sub": SUBJECT,
        "email": EMAIL,
        "email_verified": True,
        "name": "Test User",
    }
    body.update(overrides)
    for key, value in list(body.items()):
        if value is _DROP:
            del body[key]
    return json.dumps(body).encode("utf-8")


def _http_error(code: int = 500) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(USERINFO_URL, code, "server error", None, None)


# -- value object ---------------------------------------------------------------


def test_profile_is_frozen_and_compares_by_value() -> None:
    profile = CognitoProfile(
        sub=SUBJECT, email=EMAIL, email_verified=True, display_name="Test User"
    )
    assert profile == dataclasses.replace(profile)
    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.email = "other@example.com"  # type: ignore[misc]


def test_client_satisfies_profile_source_protocol() -> None:
    client = CognitoUserInfoClient(USERINFO_URL)
    assert isinstance(client, ProfileSource)


# -- constructor configuration ----------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:9999/oauth2/userInfo",  # cleartext
        "localhost:9999/oauth2/userInfo",  # no scheme
        "/oauth2/userInfo",  # relative
    ],
)
def test_non_https_endpoint_rejected_at_construction(url: str) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        CognitoUserInfoClient(url)


def test_https_endpoint_without_netloc_rejected() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        CognitoUserInfoClient("https:///oauth2/userInfo")


@pytest.mark.parametrize("url", [USERINFO_URL + "?access_token=abc", USERINFO_URL + "#frag"])
def test_query_or_fragment_smuggling_rejected(url: str) -> None:
    with pytest.raises(ValueError, match="query or fragment"):
        CognitoUserInfoClient(url)


@pytest.mark.parametrize("timeout", [0, -1.0])
def test_non_positive_timeout_rejected(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        CognitoUserInfoClient(USERINFO_URL, timeout_seconds=timeout)


def test_constructed_client_exposes_fixed_endpoint() -> None:
    assert CognitoUserInfoClient(USERINFO_URL).userinfo_url == USERINFO_URL


# -- happy path request + parsing -----------------------------------------------------


def test_fetch_sends_single_fixed_bearer_get_and_parses_profile() -> None:
    opener = _FakeOpener(response=_FakeResponse(_profile_body()))
    client = _client(opener, timeout_seconds=2.5)

    profile = client.fetch(ACCESS_TOKEN, SUBJECT)

    (request, timeout) = opener.calls[0]
    assert len(opener.calls) == 1
    assert request.full_url == USERINFO_URL
    assert request.get_method() == "GET"
    assert request.get_header("Authorization") == f"Bearer {ACCESS_TOKEN}"
    assert request.get_header("Accept") == "application/json"
    assert timeout == 2.5
    assert profile == CognitoProfile(
        sub=SUBJECT, email=EMAIL, email_verified=True, display_name="Test User"
    )


@pytest.mark.parametrize("name", [_DROP, None, ""])
def test_absent_null_or_empty_name_normalizes_to_none(name: Any) -> None:
    opener = _FakeOpener(response=_FakeResponse(_profile_body(name=name)))
    profile = _client(opener).fetch(ACCESS_TOKEN, SUBJECT)
    assert profile.display_name is None


@pytest.mark.parametrize("email", [_DROP, None])
def test_absent_or_null_email_is_none_not_a_failure(email: Any) -> None:
    opener = _FakeOpener(response=_FakeResponse(_profile_body(email=email)))
    profile = _client(opener).fetch(ACCESS_TOKEN, SUBJECT)
    assert profile.email is None


# -- subject pinning and claim shape -----------------------------------------------------


def test_subject_mismatch_rejected_with_fixed_reason() -> None:
    opener = _FakeOpener(response=_FakeResponse(_profile_body()))
    with pytest.raises(TokenValidationError) as excinfo:
        _client(opener).fetch(ACCESS_TOKEN, "someone-else")
    assert excinfo.value.reason == "profile subject does not match the token"


@pytest.mark.parametrize("sub", [_DROP, None])
def test_missing_sub_rejected(sub: Any) -> None:
    opener = _FakeOpener(response=_FakeResponse(_profile_body(sub=sub)))
    with pytest.raises(TokenValidationError, match="profile is missing the sub claim"):
        _client(opener).fetch(ACCESS_TOKEN, SUBJECT)


@pytest.mark.parametrize("sub", ["", 123, "x" * 256])
def test_malformed_sub_rejected(sub: Any) -> None:
    opener = _FakeOpener(response=_FakeResponse(_profile_body(sub=sub)))
    with pytest.raises(TokenValidationError, match="profile sub claim is invalid"):
        _client(opener).fetch(ACCESS_TOKEN, SUBJECT)


@pytest.mark.parametrize("email", ["", 42, "x" * 321])
def test_malformed_email_rejected(email: Any) -> None:
    opener = _FakeOpener(response=_FakeResponse(_profile_body(email=email)))
    with pytest.raises(TokenValidationError, match="profile email claim is invalid"):
        _client(opener).fetch(ACCESS_TOKEN, SUBJECT)


@pytest.mark.parametrize("verified", [_DROP, None])
def test_missing_email_verified_rejected(verified: Any) -> None:
    opener = _FakeOpener(response=_FakeResponse(_profile_body(email_verified=verified)))
    with pytest.raises(TokenValidationError) as excinfo:
        _client(opener).fetch(ACCESS_TOKEN, SUBJECT)
    assert excinfo.value.reason == "profile is missing the email_verified claim"


@pytest.mark.parametrize("verified", ["TRUE", "yes", "1", 1, 0])
def test_malformed_email_verified_rejected(verified: Any) -> None:
    """Only JSON booleans and Cognito's exact lowercase strings are accepted."""
    opener = _FakeOpener(response=_FakeResponse(_profile_body(email_verified=verified)))
    with pytest.raises(TokenValidationError) as excinfo:
        _client(opener).fetch(ACCESS_TOKEN, SUBJECT)
    assert excinfo.value.reason == "profile email_verified claim is invalid"


def test_false_email_verified_parses_and_is_gated_by_the_consumer() -> None:
    opener = _FakeOpener(response=_FakeResponse(_profile_body(email_verified=False)))
    profile = _client(opener).fetch(ACCESS_TOKEN, SUBJECT)
    assert profile.email_verified is False


@pytest.mark.parametrize(("wire_value", "expected"), [("true", True), ("false", False)])
def test_cognito_string_email_verified_is_normalized(wire_value: str, expected: bool) -> None:
    opener = _FakeOpener(response=_FakeResponse(_profile_body(email_verified=wire_value)))
    profile = _client(opener).fetch(ACCESS_TOKEN, SUBJECT)
    assert profile.email_verified is expected


@pytest.mark.parametrize("name", [7, "x" * 256])
def test_malformed_name_rejected(name: Any) -> None:
    opener = _FakeOpener(response=_FakeResponse(_profile_body(name=name)))
    with pytest.raises(TokenValidationError, match="profile name claim is invalid"):
        _client(opener).fetch(ACCESS_TOKEN, SUBJECT)


@pytest.mark.parametrize("token", ["", None])
def test_empty_access_token_never_reaches_the_wire(token: Any) -> None:
    opener = _FakeOpener(response=_FakeResponse(_profile_body()))
    with pytest.raises(TokenValidationError, match="profile request requires an access token"):
        _client(opener).fetch(token, SUBJECT)
    assert opener.calls == []


# -- transport / response failures -------------------------------------------------------


@pytest.mark.parametrize("code", [302, 401, 500])
def test_any_http_error_status_is_provider_unavailable(code: int) -> None:
    opener = _FakeOpener(error=_http_error(code))
    with pytest.raises(TokenProviderUnavailableError) as excinfo:
        _client(opener).fetch(ACCESS_TOKEN, SUBJECT)
    assert excinfo.value.reason == "profile endpoint returned an error response"


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
        _client(opener).fetch(ACCESS_TOKEN, SUBJECT)
    assert excinfo.value.reason == "profile endpoint could not be reached"


def test_unparseable_body_is_provider_unavailable() -> None:
    opener = _FakeOpener(response=_FakeResponse(b"<html>not json</html>"))
    with pytest.raises(TokenProviderUnavailableError) as excinfo:
        _client(opener).fetch(ACCESS_TOKEN, SUBJECT)
    assert excinfo.value.reason == "profile response is not a valid JSON document"


def test_json_array_body_is_provider_unavailable() -> None:
    opener = _FakeOpener(response=_FakeResponse(b"[]"))
    with pytest.raises(TokenProviderUnavailableError) as excinfo:
        _client(opener).fetch(ACCESS_TOKEN, SUBJECT)
    assert excinfo.value.reason == "profile response is not a JSON object"


def test_oversized_body_rejected_before_parsing() -> None:
    body = b"x" * (_MAX_PROFILE_BODY_BYTES + 1)
    opener = _FakeOpener(response=_FakeResponse(body))
    with pytest.raises(TokenProviderUnavailableError) as excinfo:
        _client(opener).fetch(ACCESS_TOKEN, SUBJECT)
    assert excinfo.value.reason == "profile response is too large"


# -- hygiene and redirect policy -----------------------------------------------------------


def test_exception_text_never_carries_token_email_or_subject() -> None:
    cases: list[Callable[[], Any]] = [
        lambda: _client(_FakeOpener(response=_FakeResponse(_profile_body()))).fetch(
            ACCESS_TOKEN, "other-sub"
        ),
        lambda: _client(_FakeOpener(error=_http_error())).fetch(ACCESS_TOKEN, SUBJECT),
        lambda: _client(_FakeOpener(response=_FakeResponse(_profile_body(email="x" * 321)))).fetch(
            ACCESS_TOKEN, SUBJECT
        ),
    ]
    for call in cases:
        with pytest.raises((TokenValidationError, TokenProviderUnavailableError)) as excinfo:
            call()
        text = str(excinfo.value)
        assert ACCESS_TOKEN not in text
        assert EMAIL not in text
        assert SUBJECT not in text


def test_redirect_handler_declines_every_redirect() -> None:
    handler = _RejectRedirectHandler()
    request = urllib.request.Request(USERINFO_URL, method="GET")
    for code in (301, 302, 303, 307, 308):
        declined = handler.redirect_request(
            request, None, code, "moved", None, "https://evil.example/redirect"
        )
        assert declined is None


# -- provisioning-profile gate (task-1 rules) ------------------------------------------------


def _gate_profile(
    *,
    sub: Any = SUBJECT,
    email: Any = "verified@example.com",
    email_verified: Any = True,
    display_name: Any = "Verified Person",
) -> CognitoProfile:
    return CognitoProfile(
        sub=sub,
        email=email,
        email_verified=email_verified,
        display_name=display_name,
    )


def test_gate_accepts_valid_profile_and_returns_it_unchanged() -> None:
    profile = _gate_profile()
    assert require_provisioning_profile(profile, token_sub=SUBJECT) is profile
    assert (
        require_provisioning_profile(
            _gate_profile(display_name=None), token_sub=SUBJECT
        ).display_name
        is None
    )


@pytest.mark.parametrize("sub", ["", 123, "x" * 256], ids=["empty", "non-string", "oversized"])
def test_gate_rejects_invalid_sub(sub: Any) -> None:
    with pytest.raises(TokenValidationError, match="sub claim is invalid"):
        require_provisioning_profile(_gate_profile(sub=sub), token_sub=SUBJECT)


def test_gate_rejects_subject_mismatch() -> None:
    with pytest.raises(TokenValidationError, match="subject does not match"):
        require_provisioning_profile(_gate_profile(sub="someone-else"), token_sub=SUBJECT)


def test_gate_requires_email_present() -> None:
    with pytest.raises(TokenValidationError, match="missing the email claim"):
        require_provisioning_profile(_gate_profile(email=None), token_sub=SUBJECT)


@pytest.mark.parametrize("email", ["", 123, "x" * 321], ids=["empty", "non-string", "oversized"])
def test_gate_rejects_invalid_email(email: Any) -> None:
    with pytest.raises(TokenValidationError, match="email claim is invalid"):
        require_provisioning_profile(_gate_profile(email=email), token_sub=SUBJECT)


@pytest.mark.parametrize("verified", [1, "true", None], ids=["int-true", "string", "null"])
def test_gate_rejects_non_boolean_email_verified(verified: Any) -> None:
    with pytest.raises(TokenValidationError, match="email_verified claim is invalid"):
        require_provisioning_profile(_gate_profile(email_verified=verified), token_sub=SUBJECT)


def test_gate_rejects_unverified_email() -> None:
    with pytest.raises(TokenValidationError, match="email is not verified"):
        require_provisioning_profile(_gate_profile(email_verified=False), token_sub=SUBJECT)


@pytest.mark.parametrize(
    "display_name", ["", 123, "x" * 256], ids=["empty", "non-string", "oversized"]
)
def test_gate_rejects_invalid_display_name(display_name: Any) -> None:
    with pytest.raises(TokenValidationError, match="display name is invalid"):
        require_provisioning_profile(_gate_profile(display_name=display_name), token_sub=SUBJECT)


def test_gate_reasons_never_carry_email_or_subject_values() -> None:
    failures: list[Callable[[], Any]] = [
        lambda: require_provisioning_profile(_gate_profile(sub=""), token_sub=SUBJECT),
        lambda: require_provisioning_profile(_gate_profile(sub="other"), token_sub=SUBJECT),
        lambda: require_provisioning_profile(_gate_profile(email=None), token_sub=SUBJECT),
        lambda: require_provisioning_profile(_gate_profile(email=""), token_sub=SUBJECT),
        lambda: require_provisioning_profile(
            _gate_profile(email_verified=False), token_sub=SUBJECT
        ),
        lambda: require_provisioning_profile(_gate_profile(display_name=""), token_sub=SUBJECT),
    ]
    for call in failures:
        with pytest.raises(TokenValidationError) as excinfo:
            call()
        text = str(excinfo.value)
        assert SUBJECT not in text
        assert "other" not in text
        assert "verified@example.com" not in text
