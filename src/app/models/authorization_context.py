"""``AuthorizationContext`` — the single internal authorization
representation every authentication mechanism resolves to (spec §10).

Phase 01 contract notes:

- ``actor_type`` values are exactly the §10 strings ``user`` and ``api_key``.
  They are a :data:`~typing.Literal`, not a member of the pinned enum set
  (the Phase 01 Planner decisions enumerate every *stored* enum; ``actor_type``
  is a transient context discriminator that never lands in a status column).
- ``actor_id`` is the task-2 :data:`~app.models.ids.ActorId` union: a ``usr_``
  or ``key_`` application identity — never a record ID (``extid_``/``mem_``/
  ``aud_``) and never a provider subject (AGENTS.md).
- Consistency rule: ``actor_type`` must match the concrete class of
  ``actor_id`` (``user`` ↔ ``UserId``, ``api_key`` ↔ ``ApiKeyId``).
- Future providers (e.g. Shopify) must resolve into this same shape; that is
  a Phase 04+ auth concern, not a model extension.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from app.models.api_key import Scope
from app.models.enums import MembershipRole
from app.models.ids import ActorId, ApiKeyId, OrganizationId, UserId

#: The two actor kinds defined by spec §10.
ActorType = Literal["user", "api_key"]


def ensure_actor_id_matches_actor_type(actor_type: ActorType, actor_id: ActorId) -> None:
    """Raise ``ValueError`` unless ``actor_id``'s concrete type matches the actor kind.

    Shared by :class:`AuthorizationContext` and
    :class:`~app.models.audit_event.AuditEvent` so the §10 invariant has a
    single source.
    """
    expected = UserId if actor_type == "user" else ApiKeyId
    if not isinstance(actor_id, expected):
        raise ValueError(
            f"actor_type {actor_type!r} requires an {expected.__name__} "
            f"actor_id, got {type(actor_id).__name__}"
        )


def actor_type_for(actor_id: ActorId) -> ActorType:
    """Derive the §10 actor kind from the concrete class of ``actor_id``.

    The inverse direction of :func:`ensure_actor_id_matches_actor_type`
    (which validates a given pair): callers that *hold* an actor identity
    and must build a consistent ``actor_type``/``actor_id`` pair — e.g. the
    generalized denial-audit builders (Phase 05 decision 7) — use this so
    the derivation shares the same single source as the validation.
    Raises ``ValueError`` for anything that is not a ``UserId``/``ApiKeyId``
    (record IDs and plain strings are never actor identities).
    """
    if isinstance(actor_id, UserId):
        return "user"
    if isinstance(actor_id, ApiKeyId):
        return "api_key"
    raise ValueError(f"not an actor identity (usr_/key_ expected): {type(actor_id).__name__}")


class AuthorizationContext(BaseModel):
    """Resolved authorization for one request: who acts, in which org, with what."""

    model_config = ConfigDict(extra="forbid")

    actor_type: ActorType
    actor_id: ActorId
    organization_id: OrganizationId
    roles: list[MembershipRole]
    scopes: list[Scope]

    @model_validator(mode="after")
    def _actor_id_matches_actor_type(self) -> AuthorizationContext:
        ensure_actor_id_matches_actor_type(self.actor_type, self.actor_id)
        return self


__all__ = [
    "ActorType",
    "AuthorizationContext",
    "actor_type_for",
    "ensure_actor_id_matches_actor_type",
]
