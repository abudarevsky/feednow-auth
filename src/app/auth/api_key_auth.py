"""API-key verification seam and context resolution (Phase 05 task 3; spec §8/§10).

The pure, in-process half of the credential boundary: a bearer literal comes
in, an :class:`~app.models.api_key.ApiKey` plus its §10
:class:`~app.models.authorization_context.AuthorizationContext` come out, or
one uniform authentication failure is raised. No FastAPI import lives here —
HTTP translation (the 401 envelope) is the dependency/router layer's job
(task 5/6), and this module keeps the auth boundary free of framework
coupling so the same seam is reusable by in-process authorizers (the phase
Handoff).

Verification pipeline (spec §8 flow, breakdown decision 4) runs in a **fixed
order** so no failure branch is distinguishable from any other on either the
message or the timing axis:

1. **Parse** the literal (:func:`~app.auth.credentials.parse_literal`): a bad
   environment prefix, a missing/empty segment, a key-id outside the pinned
   Crockford-26 shape, or an empty secret is a format failure — resolved
   before any secret material is touched or any storage read runs.
2. **Point lookup** by the non-secret §8 key-id segment
   (:meth:`~app.storage.contract.Storage.get_api_key_by_key_id`). On a miss
   the pipeline still performs a **dummy constant-time comparison** of the
   supplied secret's peppered HMAC against a fixed same-shape digest
   (:func:`~app.auth.credentials.dummy_secret_matches`) before failing, so
   "key id not found" and "secret mismatch" take indistinguishable time —
   oracle-freedom on the timing axis, not just the message axis.
3. **Secret match**: ``hmac.compare_digest`` of the recomputed peppered HMAC
   against the stored ``secret_hash`` (:func:`~app.auth.credentials.secret_matches`).
4. **Environment match**: the parsed ``fn_live``/``fn_test`` must equal the
   stored ``environment`` (defense in depth against an inconsistent row).
5. **Status**: the stored ``status`` must be ``active``.
6. **Expiry** (derived, never a stored status): ``expires_at`` is ``None`` or
   strictly in the future; the boundary ``expires_at == now`` is **expired**
   (the ``<=`` comparison is pinned here and asserted by the boundary test).

Every failure — format, unknown key, mismatched secret, environment skew,
revocation, expiry — raises the one :class:`ApiKeyAuthenticationError` with
the single fixed message :data:`API_KEY_AUTHENTICATION_MESSAGE`. No branch
message, and no key-id, secret, or pepper fragment ever enters an exception
text, cause, or context. Any other :class:`~app.storage.contract.StorageError`
(a backend outage, not a bad credential) propagates **untranslated** per
decision 11 so it surfaces as a 500, never a misleading 401.

**Organization status and scopes are authorization, not authentication.**
They are enforced by the access dependency (task 5), where denials ride the
Phase 04 uniform audited 403; this module only answers "is this a valid,
active, unexpired credential, and what context does it carry".
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Final

from app.auth.credentials import (
    ApiKeyCredentialFormatError,
    dummy_secret_matches,
    parse_literal,
    secret_matches,
)
from app.auth.pepper import PepperSource
from app.models.api_key import ApiKey, Scope
from app.models.authorization_context import AuthorizationContext
from app.models.enums import ApiKeyStatus
from app.models.timestamps import utc_now
from app.storage.contract import EntityNotFoundError, Storage

#: The single fixed, credential-free message for every authentication failure
#: (decision 4). Routers render it as the one uniform 401 ``unauthenticated``;
#: nothing here distinguishes *which* step failed.
API_KEY_AUTHENTICATION_MESSAGE: Final = "invalid API key credentials"


class ApiKeyAuthenticationError(Exception):
    """Raised for every API-key authentication failure, uniformly.

    The message is always :data:`API_KEY_AUTHENTICATION_MESSAGE` — a fixed,
    log-safe description that never echoes the key-id, secret, or pepper
    (AGENTS.md: no credential material in errors or logs). The pipeline is
    deliberately built so this is the *only* exception a failing verification
    can raise, which is what makes the "rejected without leaking which secret
    segment failed" acceptance criterion hold on both the message and timing
    axes.
    """

    def __init__(self, message: str = API_KEY_AUTHENTICATION_MESSAGE) -> None:
        super().__init__(message)


@dataclass(frozen=True)
class VerifiedApiKey:
    """The outcome of one successful verification: the row plus its context.

    ``api_key`` is the stored credential row (the caller may read
    ``organization_id``/``id``/``scopes`` for downstream authorization);
    ``context`` is the §10 :class:`AuthorizationContext` derived from it via
    :func:`build_api_key_context`. Neither carries the plaintext secret — it
    is never returned past the one-time creation path (spec §15).
    """

    api_key: ApiKey
    context: AuthorizationContext


def build_api_key_context(api_key: ApiKey) -> AuthorizationContext:
    """Derive the §10 API-key ``AuthorizationContext`` (decision 5).

    ``actor_type`` is ``"api_key"`` and ``actor_id`` is the key's ``key_``
    **application identity** (``api_key.id``) — never the creator ``usr_`` and
    never the record's non-secret ``key_id`` credential segment. ``roles`` is
    **always empty**: the creator's memberships are never consulted, which is
    the structural "no human role escalation" proof. ``organization_id`` and
    ``scopes`` come straight from the stored (already normalized) row.
    """
    return AuthorizationContext(
        actor_type="api_key",
        actor_id=api_key.id,
        organization_id=api_key.organization_id,
        roles=[],
        scopes=list(api_key.scopes),
    )


def verify_api_key(
    storage: Storage,
    pepper_source: PepperSource,
    literal: str,
    *,
    now: datetime | None = None,
) -> VerifiedApiKey:
    """Verify one credential ``literal`` against ``storage`` or fail uniformly.

    Runs the fixed pipeline documented at module scope (decision 4). The
    pepper is resolved exactly once per verification (after the format check,
    so a malformed token never touches the secret source) and reused for both
    the real and the dummy comparison, keeping the two branches
    work-identical. ``now`` is injectable for deterministic expiry tests and
    defaults to one :func:`~app.models.timestamps.utc_now` read taken only
    when the key actually carries an ``expires_at``.

    Returns a :class:`VerifiedApiKey` on success.

    Raises:
        ApiKeyAuthenticationError: on any authentication failure — malformed
            literal, unknown key-id, wrong secret, environment skew, revoked,
            or expired — always with the single fixed message.
        StorageError: any non-``EntityNotFoundError`` storage failure (e.g. a
            backend outage) propagates untranslated (decision 11 → 500).
    """
    try:
        parsed = parse_literal(literal)
    except ApiKeyCredentialFormatError:
        # Format failure precedes any secret-source or storage touch; the
        # underlying error never echoes input, and ``from None`` keeps even
        # the suppressed context out of the traceback.
        raise ApiKeyAuthenticationError() from None

    pepper = pepper_source.current()
    try:
        api_key = storage.get_api_key_by_key_id(parsed.key_id)
    except EntityNotFoundError:
        # Equalize the unknown-key timing branch against a real comparison
        # (decision 4): identical HMAC + constant-time work against a digest
        # no achievable input matches, then the one uniform failure.
        dummy_secret_matches(pepper, parsed.secret)
        raise ApiKeyAuthenticationError() from None

    if not secret_matches(api_key.secret_hash, pepper, parsed.secret):
        raise ApiKeyAuthenticationError()
    if parsed.environment is not api_key.environment:
        raise ApiKeyAuthenticationError()
    if api_key.status is not ApiKeyStatus.ACTIVE:
        raise ApiKeyAuthenticationError()
    if api_key.expires_at is not None:
        reference = now if now is not None else utc_now()
        # Boundary pinned: ``expires_at == now`` is expired (``<=``).
        if api_key.expires_at <= reference:
            raise ApiKeyAuthenticationError()

    return VerifiedApiKey(api_key=api_key, context=build_api_key_context(api_key))


def key_has_scope(context: AuthorizationContext, scope: Scope) -> bool:
    """Return whether ``context`` carries ``scope`` (decision 7: exact match).

    API-key scope enforcement is exact string membership — no wildcards, no
    hierarchy (spec §9 defines none, and inventing ``vispector:*`` would be
    smuggled entitlement semantics). Human contexts carry an empty scope
    list, so this is always ``False`` for them; the scope dependency (task 5)
    only consults it on the API-key branch.
    """
    return scope in context.scopes


__all__ = [
    "API_KEY_AUTHENTICATION_MESSAGE",
    "ApiKeyAuthenticationError",
    "VerifiedApiKey",
    "build_api_key_context",
    "key_has_scope",
    "verify_api_key",
]
