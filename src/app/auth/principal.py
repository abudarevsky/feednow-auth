"""Unified ``Principal`` — the actor one authenticated request resolves to
(API-key; authorization-context contract, design notes design choice 6).

One request, one actor: either a human :class:`~app.models.user.User`
(authenticated by the unchanged identity JWT chain) or an
:class:`~app.models.api_key.ApiKey` credential (authenticated by the implementation
verification seam). :class:`Principal` is the discriminated wrapper the
dependency layer hands to the access dependencies, and the single place the
"exactly one actor" invariant is enforced structurally:

- ``user`` and ``api_key`` are mutually exclusive and jointly required —
  exactly one must be set, checked in :meth:`__post_init__` (a both-``None``
  or both-set principal is a programming error, never a silent state);
- ``context`` is the authorization-context contract :class:`~app.models.authorization_context.AuthorizationContext`
  for whichever actor is present: on the human path it wraps the unchanged
  identity :class:`~app.services.identity.ResolvedIdentity` pair (the same
  ``user``/``context`` objects ``build_current_user`` yields), on the API-key
  path it is the implementation ``build_api_key_context`` output (``roles == []``,
  stored scopes — design choice 5). Consumers must read the actor kind from the
  context (or the ``user``/``api_key`` fields), never from a token shape.

Like the identity and organizationseams, nothing here carries plaintext credential
material: ``api_key`` is the stored row (peppered ``secret_hash`` only), and
the human fields are the domain models themselves.

Current behavior and invariants: ``docs/authentication.md``."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.api_key import ApiKey
from app.models.authorization_context import AuthorizationContext
from app.models.user import User


@dataclass(frozen=True)
class Principal:
    """Exactly one authenticated actor plus its authorization-context contract authorization context."""

    user: User | None
    api_key: ApiKey | None
    context: AuthorizationContext

    def __post_init__(self) -> None:
        """Enforce the one-actor invariant (design choice 6).

        The message names only which fields were set — no model content, so
        no email or credential material can ever ride an invariant failure.
        """
        if (self.user is None) == (self.api_key is None):
            raise ValueError(
                "Principal requires exactly one actor set: "
                f"user={'set' if self.user is not None else 'None'}, "
                f"api_key={'set' if self.api_key is not None else 'None'}"
            )


__all__ = ["Principal"]
