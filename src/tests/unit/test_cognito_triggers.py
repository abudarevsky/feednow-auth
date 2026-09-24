"""Unit proofs for the Cognito user-pool registration triggers.

The module under test (``src/app/auth/cognito_triggers.py``) is the trigger
handler code for the pre sign-up and post confirmation registration events.
Tests drive it with Cognito-shaped event mappings (the sanctioned fixture
style of ``tests/support/cognito.py``: shaped payloads, never a live pool):

1. Envelope parsing: the happy projection into ``CognitoRegistrationEvent``
   and the identical fixed failure for every malformed member.
2. Pre sign-up: all three ``PreSignUp_*`` registration sources accepted with a
   bounded email (input never mutated, ``response`` stays an empty object —
   no auto-confirm/auto-verify), and every email rule violation rejected.
3. Post confirmation: the sign-up source is validated and passed through; the
   non-registration sources (forgot password, verify attribute) pass through
   even without an email; foreign sources fail closed.
4. The Lambda entry point dispatches by ``triggerSource`` prefix and rejects
   anything outside the two registration triggers.
5. Secrecy: fixed messages echo no attribute material; the module imports no
   logging (AST proof) and emits zero log records (caplog proof).
"""

from __future__ import annotations

import ast
import copy
import logging
from pathlib import Path
from typing import Any, Final

import pytest

import app.auth.cognito_triggers as triggers_module
from app.auth.cognito_triggers import (
    EMAIL_MAX_LENGTH,
    EMAIL_MISSING_MESSAGE,
    EMAIL_TOO_LONG_MESSAGE,
    EVENT_STRUCTURE_MESSAGE,
    NON_REGISTRATION_POST_CONFIRMATION_SOURCES,
    TRIGGER_UNSUPPORTED_MESSAGE,
    CognitoRegistrationEvent,
    CognitoTriggerRejectionError,
    cognito_trigger_handler,
    handle_post_confirmation,
    handle_pre_sign_up,
    parse_cognito_trigger_event,
)

USER_EMAIL: Final = "new-signup@example.com"
USER_POOL_ID: Final = "eu-north-1_EXAMPLE"
CLIENT_ID: Final = "apitestclient0000000000"

PRE_SIGN_UP_SOURCES: Final = [
    "PreSignUp_SignUp",
    "PreSignUp_AdminCreateUser",
    "PreSignUp_ExternalProvider",
]


def _event(trigger_source: str, *, email: object = USER_EMAIL) -> dict[str, Any]:
    """One Cognito-shaped registration trigger event.

    ``email`` is injected into ``userAttributes`` as given so tests can send
    missing/blank/oversized/non-string values; every other member is a valid
    real-world shape.
    """
    attributes: dict[str, Any] = {
        "sub": "11111111-2222-3333-4444-555555555555",
        "email_verified": False,
        "status": "unconfirmed",
    }
    if email is not ...:
        attributes["email"] = email
    return {
        "version": "1",
        "region": "eu-north-1",
        "userPoolId": USER_POOL_ID,
        "userName": USER_EMAIL if isinstance(email, str) and email else "throwaway-name",
        "callerContext": {"awsSdkVersion": "aws-sdk-unknown-unknown", "clientId": CLIENT_ID},
        "triggerSource": trigger_source,
        "request": {"userAttributes": attributes},
        "response": {},
    }


# ---------------------------------------------------------------------------
# 1. Envelope parsing
# ---------------------------------------------------------------------------


def test_parse_projects_the_common_envelope() -> None:
    parsed = parse_cognito_trigger_event(_event("PreSignUp_SignUp"))
    assert isinstance(parsed, CognitoRegistrationEvent)
    assert parsed.version == "1"
    assert parsed.region == "eu-north-1"
    assert parsed.user_pool_id == USER_POOL_ID
    assert parsed.client_id == CLIENT_ID
    assert parsed.trigger_source == "PreSignUp_SignUp"
    assert parsed.user_attributes["email"] == USER_EMAIL


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("version",), ""),
        (("version",), "2"),
        (("region",), ""),
        (("userPoolId",), None),
        (("userName",), 123),
        (("triggerSource",), ""),
        (("callerContext",), "not-a-mapping"),
        (("callerContext", "clientId"), ""),
        (("request",), None),
        (("request", "userAttributes"), []),
    ],
)
def test_parse_rejects_every_malformed_member_identically(
    path: tuple[str, ...], value: object
) -> None:
    event = _event("PreSignUp_SignUp")
    target: dict[str, Any] = event
    for key in path[:-1]:
        target = target[key]  # type: ignore[assignment]
    if value is None:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    with pytest.raises(CognitoTriggerRejectionError) as excinfo:
        parse_cognito_trigger_event(event)
    assert str(excinfo.value) == EVENT_STRUCTURE_MESSAGE


def test_parse_rejects_non_mapping_events() -> None:
    for event in (None, "event", 42):
        with pytest.raises(CognitoTriggerRejectionError) as excinfo:
            parse_cognito_trigger_event(event)  # type: ignore[arg-type]
        assert str(excinfo.value) == EVENT_STRUCTURE_MESSAGE


# ---------------------------------------------------------------------------
# 2. Pre sign-up
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source", PRE_SIGN_UP_SOURCES)
def test_pre_sign_up_accepts_registration_sources(source: str) -> None:
    event = _event(source)
    snapshot = copy.deepcopy(event)
    result = handle_pre_sign_up(event)
    assert result == snapshot  # pass-through: same content ...
    assert result is not event  # ... on a copy; the input is never mutated
    assert result["response"] == {}  # no auto-confirm, no auto-verify
    assert snapshot["response"] == {}


def test_pre_sign_up_accepts_email_at_the_bound() -> None:
    email = "a" * (EMAIL_MAX_LENGTH - len("@example.com")) + "@example.com"
    assert len(email) == EMAIL_MAX_LENGTH
    assert handle_pre_sign_up(_event("PreSignUp_SignUp", email=email))


@pytest.mark.parametrize("source", PRE_SIGN_UP_SOURCES)
@pytest.mark.parametrize("email", [..., "", "   x" * 200, 42, True, ["a@example.com"]])
def test_pre_sign_up_rejects_bad_email_attributes(source: str, email: object) -> None:
    too_long = isinstance(email, str) and len(email) > EMAIL_MAX_LENGTH
    expected = EMAIL_TOO_LONG_MESSAGE if too_long else EMAIL_MISSING_MESSAGE
    with pytest.raises(CognitoTriggerRejectionError) as excinfo:
        handle_pre_sign_up(_event(source, email=email))
    assert str(excinfo.value) == expected


def test_pre_sign_up_rejects_post_confirmation_sources() -> None:
    with pytest.raises(CognitoTriggerRejectionError) as excinfo:
        handle_pre_sign_up(_event("PostConfirmation_ConfirmSignUp"))
    assert str(excinfo.value) == TRIGGER_UNSUPPORTED_MESSAGE


# ---------------------------------------------------------------------------
# 3. Post confirmation
# ---------------------------------------------------------------------------


def test_post_confirmation_validates_and_passes_through_the_registration_event() -> None:
    event = _event("PostConfirmation_ConfirmSignUp", email="confirmed@example.com")
    snapshot = copy.deepcopy(event)
    result = handle_post_confirmation(event)
    assert result == snapshot
    assert result is not event


def test_post_confirmation_rejects_a_registration_without_email() -> None:
    with pytest.raises(CognitoTriggerRejectionError) as excinfo:
        handle_post_confirmation(_event("PostConfirmation_ConfirmSignUp", email=...))
    assert str(excinfo.value) == EMAIL_MISSING_MESSAGE


@pytest.mark.parametrize("source", sorted(NON_REGISTRATION_POST_CONFIRMATION_SOURCES))
def test_post_confirmation_passes_non_registration_sources_through_unvalidated(
    source: str,
) -> None:
    # No email attribute at all: a password reset or attribute verification
    # must never be failed by the registration trigger.
    event = _event(source, email=...)
    assert handle_post_confirmation(event) == event


def test_handler_backfills_a_missing_response_object() -> None:
    event = _event("PostConfirmation_ConfirmForgotPassword", email=...)
    del event["response"]
    result = handle_post_confirmation(event)
    assert result["response"] == {}
    assert "response" not in event  # the input mapping is never mutated


def test_post_confirmation_rejects_pre_sign_up_sources() -> None:
    with pytest.raises(CognitoTriggerRejectionError) as excinfo:
        handle_post_confirmation(_event("PreSignUp_SignUp"))
    assert str(excinfo.value) == TRIGGER_UNSUPPORTED_MESSAGE


# ---------------------------------------------------------------------------
# 4. Lambda entry-point dispatch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source", PRE_SIGN_UP_SOURCES)
def test_handler_dispatches_pre_sign_up_sources(source: str) -> None:
    assert cognito_trigger_handler(_event(source), None) == _event(source)


def test_handler_dispatches_post_confirmation_sources() -> None:
    assert cognito_trigger_handler(_event("PostConfirmation_ConfirmSignUp"), None)


@pytest.mark.parametrize(
    "source",
    ["CustomMessage_SignUp", "PreAuthentication_Authentication", "Define_Auth_Challenge"],
)
def test_handler_fails_closed_on_foreign_triggers(source: str) -> None:
    with pytest.raises(CognitoTriggerRejectionError) as excinfo:
        cognito_trigger_handler(_event(source), None)
    assert str(excinfo.value) == TRIGGER_UNSUPPORTED_MESSAGE


@pytest.mark.parametrize("event", [None, {}, {"triggerSource": 42}])
def test_handler_fails_closed_on_unroutable_events(event: object) -> None:
    with pytest.raises(CognitoTriggerRejectionError):
        cognito_trigger_handler(event, None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 5. Secrecy: fixed messages, no logging
# ---------------------------------------------------------------------------


def test_rejection_messages_never_echo_attribute_material() -> None:
    secret = "top-secret-signup@example.com"
    for handler, source in (
        (handle_pre_sign_up, "PreSignUp_SignUp"),
        (handle_post_confirmation, "PostConfirmation_ConfirmSignUp"),
    ):
        with pytest.raises(CognitoTriggerRejectionError) as excinfo:
            handler(_event(source, email=secret + "-overrun" + "x" * 320))
        assert secret not in str(excinfo.value)


def test_triggers_module_imports_no_logging() -> None:
    """AST proof: the module has no logging import and no logger reference."""
    tree = ast.parse(Path(triggers_module.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] != "logging" for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            assert root != "logging"
        elif isinstance(node, ast.Attribute):
            assert node.attr != "getLogger"


def test_registration_handling_emits_no_log_records(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        handle_pre_sign_up(_event("PreSignUp_SignUp"))
        handle_post_confirmation(_event("PostConfirmation_ConfirmSignUp"))
    assert caplog.records == []
    assert USER_EMAIL not in caplog.text
