"""Unified ``Principal`` — the actor one authenticated request resolves to
(Phase 05 task 5; spec §10, breakdown decision 6).

One request, one actor: either a human :class:`~app.models.user.User`
(authenticated by the unchanged Phase 03 JWT chain) or an
:class:`~app.models.api_key.ApiKey` credential (authenticated by the task-3
verification seam). :class:`Principal` is the discriminated wrapper the
dependency layer hands to the access dependencies, and the single place the
"exactly one actor" invariant is enforced structurally:

- ``user`` and ``api_key`` are mutually exclusive and jointly required —
  exactly one must be set, checked in :meth:`__post_init__` (a both-``None``
  or both-set principal is a programming error, never a silent state);
- ``context`` is the §10 :class:`~app.models.authorization_context.AuthorizationContext`
  for whichever actor is present: on the human path it wraps the unchanged
  Phase 03 :class:`~app.services.identity.ResolvedIdentity` pair (the same
  ``user``/``context`` objects ``build_current_user`` yields), on the API-key
  path it is the task-3 ``build_api_key_context`` output (``roles == []``,
  stored scopes — decision 5). Consumers must read the actor kind from the
  context (or the ``user``/``api_key`` fields), never from a token shape.

Like the Phase 03/04 seams, nothing here carries plaintext credential
material: ``api_key`` is the stored row (peppered ``secret_hash`` only), and
the human fields are the domain models themselves.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.api_key import ApiKey
from app.models.authorization_context import AuthorizationContext
from app.models.user import User


@dataclass(frozen=True)
class Principal:
    """Exactly one authenticated actor plus its §10 authorization context."""

    user: User | None
    api_key: ApiKey | None
    context: AuthorizationContext

    def __post_init__(self) -> None:
        """Enforce the one-actor invariant (decision 6).

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
