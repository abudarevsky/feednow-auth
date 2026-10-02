"""Login-state and application-session records (session, contract §session boundary).

Two frozen, provider-neutral records back the authorization-code session flow:

- :class:`OAuthLoginState` carries the single-use PKCE login state between
  ``/oauth/login`` initiation and ``/oauth/callback`` consumption. The
  ``code_verifier`` is ephemeral flow material: it is stored only until
  consumed (or expired) and must never be logged or echoed (AGENTS.md
  token-secrecy rule; the PKCE verifier is not a token but is treated with
  the same discipline).
- :class:`AppSession` is the server-side half of the opaque ``feednow_session``
  cookie. The session id carries no claims and is never an application
  identity; ``user_id`` is the internal ``usr_`` identity the session maps to.

Deliberate boundaries:

- Storage mints nothing: ids and ``expires_at`` are caller-populated exactly
  like every other persisted record (contract rule). Expiry is evaluated by
  adapters against their own clock on read/consume — reads are not writes.
- ``user_id`` is application identity enforced at the model boundary, not a
  foreign key: the storage contract declares no session→user referential
  integrity (users are never deleted, and the request-time authorization
  check re-reads user status independently of the session row).
- Id length floors (16) sit well below what the issuers mint
  (``secrets.token_urlsafe(32)`` → 43 chars) so a truncated or forged
  caller-supplied id fails validation before it ever reaches storage.

Current behavior and invariants: ``docs/architecture.md``."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from app.models.ids import UserId
from app.models.timestamps import UtcDatetime

#: Opaque OAuth login-state identifier (single-use; issued by the login route).
StateId = Annotated[str, StringConstraints(min_length=16, max_length=255)]

#: RFC 7636 code verifier: 43-128 characters of the unreserved set. The
#: issuer uses ``secrets.token_urlsafe(64)`` (86 chars); the charset is
#: enforced where the verifier is minted, not here.
CodeVerifier = Annotated[str, StringConstraints(min_length=43, max_length=128)]

#: Same-origin return URL captured at login initiation, bounded well past
#: any realistic allow-list entry. Re-validated on redirect, never trusted
#: as stored.
ReturnUrl = Annotated[str, StringConstraints(min_length=1, max_length=2048)]

#: Opaque application-session identifier (carries no claims).
SessionId = Annotated[str, StringConstraints(min_length=16, max_length=255)]


class OAuthLoginState(BaseModel):
    """One pending authorization-code login: verifier + return target.

    Consumption is get-and-delete (exactly one caller receives the record);
    a read at/past ``expires_at`` behaves as absent.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    state_id: StateId
    code_verifier: CodeVerifier
    return_url: ReturnUrl
    expires_at: UtcDatetime


class AppSession(BaseModel):
    """One issued application session mapping to a ``usr_`` identity.

    A read at/past ``expires_at`` behaves as absent; revocation beyond
    expiry is not part of this capability's contract.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: SessionId
    user_id: UserId
    expires_at: UtcDatetime


__all__ = [
    "AppSession",
    "CodeVerifier",
    "OAuthLoginState",
    "ReturnUrl",
    "SessionId",
    "StateId",
]
