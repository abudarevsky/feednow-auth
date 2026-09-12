"""``AuditEvent`` domain entity (spec §4, §16).

Records one audited action inside one organization. ``actor_type``/``actor_id``
carry the same §10 semantics as
:class:`~app.models.authorization_context.AuthorizationContext` (application
identity only; the ``aud_`` record ``id`` is internal and never an actor_id),
including the actor-type/actor-id consistency rule.

No-secrets rule (AGENTS.md; spec §16): ``metadata`` must never contain
plaintext API keys, Cognito tokens, passwords, or refresh tokens. Phase 01
types ``metadata`` as a JSON-safe mapping so adapters can persist it without
lossy conversion; **runtime redaction of sensitive values is owner-phase
work** (the services that emit audit events in Phases 03-05).

Deliberate Phase 01 boundaries:

- ``action``/``target_type`` values (e.g. ``api_key.created`` per §16) are
  bounded free strings; the canonical action vocabulary is owner-phase work.
- ``target_type``/``target_id`` are optional: not every audited action names a
  distinct target row (e.g. a broad ``authorization.denied``).
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, JsonValue, StringConstraints, model_validator

from app.models.authorization_context import (
    ActorType,
    ensure_actor_id_matches_actor_type,
)
from app.models.ids import ActorId, AuditEventId, OrganizationId
from app.models.timestamps import UtcDatetime

#: JSON-safe audit payload: nested objects/arrays are allowed, non-JSON
#: Python values (datetimes, sets, arbitrary objects) are rejected at the
#: model boundary. Must never carry secret material — see module docstring.
AuditMetadata = dict[str, JsonValue]

#: Bounded action name, e.g. ``membership.created`` (spec §16).
AuditAction = Annotated[str, StringConstraints(min_length=1, max_length=128)]

#: Bounded kind of the audited target, e.g. ``api_key``.
AuditTargetType = Annotated[str, StringConstraints(min_length=1, max_length=64)]

#: Bounded identifier of the audited target. A plain string by design: the
#: target is polymorphic (any entity, including entities Phase 01 does not
#: model), so it is not narrowed to one typed ID value object.
AuditTargetId = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class AuditEvent(BaseModel):
    """A record of one audited action (spec §4)."""

    model_config = ConfigDict(extra="forbid")

    id: AuditEventId
    organization_id: OrganizationId
    actor_type: ActorType
    actor_id: ActorId
    action: AuditAction
    target_type: AuditTargetType | None = None
    target_id: AuditTargetId | None = None
    metadata: AuditMetadata = Field(default_factory=dict)
    created_at: UtcDatetime

    @model_validator(mode="after")
    def _actor_id_matches_actor_type(self) -> AuditEvent:
        ensure_actor_id_matches_actor_type(self.actor_type, self.actor_id)
        return self


__all__ = [
    "AuditAction",
    "AuditEvent",
    "AuditMetadata",
    "AuditTargetId",
    "AuditTargetType",
]
