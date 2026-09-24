"""Cognito user-pool Lambda triggers for registration events.

This module is the trigger **handler code** for the two user-pool lifecycle
points that report a registration: **Pre sign-up** (a new local, admin-created,
or first-federated user is about to be created in the pool) and **Post
confirmation** (a signed-up user just confirmed their account). Cognito invokes
one Lambda function bound to those triggers with the JSON event documented in
the developer guide; this module parses, validates, and answers that event.

Boundary (AGENTS.md / spec 12): a Cognito trigger establishes an *external*
identity only. It never creates, mutates, or looks up a FeedNow ``User`` —
shadow registration stays where the verified-profile login flow put it
(:func:`app.services.identity.resolve_or_provision`), so a sign-up without a
first login still produces zero internal rows. Consequently this module
imports **no** storage, service, or model types: it works on the raw event
mapping with plain integer bounds mirroring the Cognito verifier's caps
(``app.auth.cognito`` decision 4), and the email rule is the provisioning
gate's rule — present and bounded, never format-validated here (``User``
docstring: format rules are owner-phase work).

Dispatch is by ``triggerSource`` (the event carries no trigger-name field):

- ``PreSignUp_*`` (:data:`TRIGGER_SOURCE_PRE_SIGN_UP`,
  :data:`TRIGGER_SOURCE_PRE_SIGN_UP_ADMIN_CREATE`,
  :data:`TRIGGER_SOURCE_PRE_SIGN_UP_EXTERNAL`) — a registration attempt. The
  envelope is validated and the email attribute is required; a failure raises
  :class:`CognitoTriggerRejectionError`, which makes Cognito deny the
  sign-up/user creation. The response is returned empty: the handler never
  auto-confirms or auto-verifies, so the pool's real email-verification flow
  (``AutoVerifiedAttributes=["email"]``) stays the only path to
  ``email_verified`` — the invariant Phase 11's provisioning gate depends on.
- ``PostConfirmation_ConfirmSignUp`` — a completed registration: validated the
  same way and returned unchanged.
- :data:`NON_REGISTRATION_POST_CONFIRMATION_SOURCES`
  (forgot-password/verify-attribute confirmations) — **not** registration
  events: the envelope is still parsed, but the email rule is skipped and the
  event passes through unchanged, so binding this function can never break
  password reset or attribute verification.
- any other source — :data:`TRIGGER_UNSUPPORTED_MESSAGE`: the function must
  only ever be bound to the two registration triggers, and it fails closed
  when invoked from anywhere else.

Secrecy rules (AGENTS.md): no logging import, no persistence, and every
rejection carries one fixed module-level message that echoes no email,
attribute, subject, or token material.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

#: The only event-schema version Cognito emits for these triggers.
TRIGGER_EVENT_VERSION: Final = "1"

#: ``triggerSource`` prefix identifying the pre sign-up trigger.
PRE_SIGN_UP_SOURCE_PREFIX: Final = "PreSignUp_"

#: ``triggerSource`` prefix identifying the post confirmation trigger.
POST_CONFIRMATION_SOURCE_PREFIX: Final = "PostConfirmation_"

#: Self-service sign-up (``SignUp`` API or Hosted UI registration).
TRIGGER_SOURCE_PRE_SIGN_UP: Final = "PreSignUp_SignUp"

#: Administrator-created user (``AdminCreateUser``).
TRIGGER_SOURCE_PRE_SIGN_UP_ADMIN_CREATE: Final = "PreSignUp_AdminCreateUser"

#: First sign-in of a federated (external-provider) user — also a registration.
TRIGGER_SOURCE_PRE_SIGN_UP_EXTERNAL: Final = "PreSignUp_ExternalProvider"

#: A signed-up user confirmed their account: the registration-completed event.
TRIGGER_SOURCE_POST_CONFIRMATION_SIGN_UP: Final = "PostConfirmation_ConfirmSignUp"

#: Post-confirmation sources that are *not* registrations. They fire on the
#: same bound function and must pass through untouched.
NON_REGISTRATION_POST_CONFIRMATION_SOURCES: Final = frozenset(
    {
        "PostConfirmation_ConfirmForgotPassword",
        "PostConfirmation_VerifyAttribute",
    }
)

#: Email length cap, mirroring the ``User`` model bound (RFC 5321 + margin).
#: A plain integer on purpose: this module imports no domain types.
EMAIL_MAX_LENGTH: Final = 320

#: Fixed, input-free rejection messages. Cognito surfaces the error string to
#: the API caller, so nothing here may ever interpolate attribute material.
EVENT_STRUCTURE_MESSAGE: Final = "cognito trigger event is malformed"
TRIGGER_UNSUPPORTED_MESSAGE: Final = "cognito trigger source is not a registration event"
EMAIL_MISSING_MESSAGE: Final = "registration requires an email attribute"
EMAIL_TOO_LONG_MESSAGE: Final = "registration email exceeds the supported length"


class CognitoTriggerRejectionError(Exception):
    """A registration event the user pool must not accept.

    Raising this from a pre sign-up handler makes Cognito deny the sign-up;
    from post confirmation it surfaces the invocation failure without
    mutating the confirmed user. ``reason`` is one fixed module-level
    message — never interpolated email, attribute, or subject material
    (AGENTS.md no-secrets rule).
    """

    def __init__(self, reason: str) -> None:
        if not reason.strip():
            raise ValueError("CognitoTriggerRejectionError reason must be a non-empty, safe string")
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class CognitoRegistrationEvent:
    """The validated common envelope of a registration trigger event.

    Holds only what the handlers read: identity-pool coordinates, the
    ``triggerSource`` discriminator, the calling client id, and the user
    attributes mapping. It is a parse result, never a credential — the
    attributes stay raw strings/bools exactly as Cognito sent them.
    """

    version: str
    region: str
    user_pool_id: str
    user_name: str
    client_id: str
    trigger_source: str
    user_attributes: Mapping[str, Any]


def _require_text(value: object) -> str:
    """Non-empty plain-string envelope member, or one fixed structure error.

    The offending member name never rides the message (fixed-reason rule), so
    every malformed envelope fails identically no matter which field broke.
    """
    if not isinstance(value, str) or not value:
        raise CognitoTriggerRejectionError(EVENT_STRUCTURE_MESSAGE)
    return value


def parse_cognito_trigger_event(event: Mapping[str, Any]) -> CognitoRegistrationEvent:
    """Validate the common trigger envelope and project it to the dataclass.

    Checks the schema version, the pool coordinates, the ``triggerSource``
    discriminator, ``callerContext.clientId``, and that
    ``request.userAttributes`` is a mapping. Every failure raises
    :class:`CognitoTriggerRejectionError` with
    :data:`EVENT_STRUCTURE_MESSAGE` — the malformed member is named in no
    message.

    Raises:
        CognitoTriggerRejectionError: the event is not a well-formed trigger.
    """
    if not isinstance(event, Mapping):
        raise CognitoTriggerRejectionError(EVENT_STRUCTURE_MESSAGE)
    version = _require_text(event.get("version"))
    if version != TRIGGER_EVENT_VERSION:
        raise CognitoTriggerRejectionError(EVENT_STRUCTURE_MESSAGE)
    region = _require_text(event.get("region"))
    user_pool_id = _require_text(event.get("userPoolId"))
    user_name = _require_text(event.get("userName"))
    trigger_source = _require_text(event.get("triggerSource"))
    caller_context = event.get("callerContext")
    if not isinstance(caller_context, Mapping):
        raise CognitoTriggerRejectionError(EVENT_STRUCTURE_MESSAGE)
    client_id = _require_text(caller_context.get("clientId"))
    request = event.get("request")
    if not isinstance(request, Mapping):
        raise CognitoTriggerRejectionError(EVENT_STRUCTURE_MESSAGE)
    user_attributes = request.get("userAttributes")
    if not isinstance(user_attributes, Mapping):
        raise CognitoTriggerRejectionError(EVENT_STRUCTURE_MESSAGE)
    return CognitoRegistrationEvent(
        version=version,
        region=region,
        user_pool_id=user_pool_id,
        user_name=user_name,
        client_id=client_id,
        trigger_source=trigger_source,
        user_attributes=user_attributes,
    )


def _require_registration_source(parsed: CognitoRegistrationEvent, *, prefix: str) -> None:
    """Pin the parsed event to the handler's own trigger prefix.

    A source from the other registration trigger (or any foreign source)
    reaching a direct handler call is a wiring bug; fail closed with the
    unsupported-source message rather than validating the wrong event shape.
    """
    if not parsed.trigger_source.startswith(prefix):
        raise CognitoTriggerRejectionError(TRIGGER_UNSUPPORTED_MESSAGE)


def _require_valid_registration_email(parsed: CognitoRegistrationEvent) -> None:
    """Enforce the pool-boundary email rule: present, string, bounded.

    Deliberately *not* format validation (owner-phase rule, see module
    docstring) and never a uniqueness claim (Phase 12: email is non-unique).
    """
    email = parsed.user_attributes.get("email")
    if not isinstance(email, str) or not email:
        raise CognitoTriggerRejectionError(EMAIL_MISSING_MESSAGE)
    if len(email) > EMAIL_MAX_LENGTH:
        raise CognitoTriggerRejectionError(EMAIL_TOO_LONG_MESSAGE)


def _event_with_response(event: Mapping[str, Any]) -> dict[str, Any]:
    """Copy ``event`` for return, guaranteeing a JSON-object ``response``.

    The input mapping is never mutated; an empty ``response`` tells Cognito to
    proceed with pool defaults (no auto-confirm, no auto-verify).
    """
    result = dict(event)
    if not isinstance(result.get("response"), dict):
        result["response"] = {}
    return result


def handle_pre_sign_up(event: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a sign-up attempt and return the event for Cognito.

    Every ``PreSignUp_*`` source (self-service, admin-created, external
    first sign-in) is a registration and must carry a bounded email
    attribute. Rejection denies the sign-up; acceptance returns the event
    with an empty ``response`` so the pool's own confirmation and real email
    verification proceed unchanged.

    Raises:
        CognitoTriggerRejectionError: malformed event, non-pre-sign-up source,
            or a missing/blank/oversized email attribute.
    """
    parsed = parse_cognito_trigger_event(event)
    _require_registration_source(parsed, prefix=PRE_SIGN_UP_SOURCE_PREFIX)
    _require_valid_registration_email(parsed)
    return _event_with_response(event)


def handle_post_confirmation(event: Mapping[str, Any]) -> dict[str, Any]:
    """Handle a post-confirmation invocation of the registration triggers.

    ``PostConfirmation_ConfirmSignUp`` completes a registration: the event is
    validated (envelope + email) and returned unchanged. The
    :data:`NON_REGISTRATION_POST_CONFIRMATION_SOURCES` pass through
    untouched — this function may observe them but must never fail a password
    reset or attribute verification. Any other source fails closed.

    Raises:
        CognitoTriggerRejectionError: malformed registration event or a
            source outside the post-confirmation trigger.
    """
    parsed = parse_cognito_trigger_event(event)
    _require_registration_source(parsed, prefix=POST_CONFIRMATION_SOURCE_PREFIX)
    if parsed.trigger_source in NON_REGISTRATION_POST_CONFIRMATION_SOURCES:
        return _event_with_response(event)
    _require_valid_registration_email(parsed)
    return _event_with_response(event)


def cognito_trigger_handler(event: Mapping[str, Any], context: object = None) -> dict[str, Any]:
    """Lambda entry point: dispatch a registration trigger event by source.

    Bind the deployed function to the user pool's **pre sign-up** and **post
    confirmation** triggers only. ``context`` is the Lambda context object,
    unused by design (the handler needs no runtime credentials — it touches no
    AWS service).

    Raises:
        CognitoTriggerRejectionError: anything not routed by the two
            registration trigger prefixes, or the routed handlers' failures.
    """
    del context  # the registration handlers perform no runtime interaction
    if isinstance(event, Mapping) and isinstance(event.get("triggerSource"), str):
        source: str = event["triggerSource"]
        if source.startswith(PRE_SIGN_UP_SOURCE_PREFIX):
            return handle_pre_sign_up(event)
        if source.startswith(POST_CONFIRMATION_SOURCE_PREFIX):
            return handle_post_confirmation(event)
    raise CognitoTriggerRejectionError(TRIGGER_UNSUPPORTED_MESSAGE)


__all__ = [
    "EMAIL_MAX_LENGTH",
    "EMAIL_MISSING_MESSAGE",
    "EMAIL_TOO_LONG_MESSAGE",
    "EVENT_STRUCTURE_MESSAGE",
    "NON_REGISTRATION_POST_CONFIRMATION_SOURCES",
    "POST_CONFIRMATION_SOURCE_PREFIX",
    "PRE_SIGN_UP_SOURCE_PREFIX",
    "TRIGGER_EVENT_VERSION",
    "TRIGGER_SOURCE_POST_CONFIRMATION_SIGN_UP",
    "TRIGGER_SOURCE_PRE_SIGN_UP",
    "TRIGGER_SOURCE_PRE_SIGN_UP_ADMIN_CREATE",
    "TRIGGER_SOURCE_PRE_SIGN_UP_EXTERNAL",
    "TRIGGER_UNSUPPORTED_MESSAGE",
    "CognitoRegistrationEvent",
    "CognitoTriggerRejectionError",
    "cognito_trigger_handler",
    "handle_post_confirmation",
    "handle_pre_sign_up",
    "parse_cognito_trigger_event",
]
