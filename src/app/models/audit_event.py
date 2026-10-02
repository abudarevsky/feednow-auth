"""``AuditEvent`` domain entity (domain model contract, audit contract).

Records one audited action inside one organization. ``actor_type``/``actor_id``
carry the same authorization-context contract semantics as
:class:`~app.models.authorization_context.AuthorizationContext` (application
identity only; the ``aud_`` record ``id`` is internal and never an actor_id),
including the actor-type/actor-id consistency rule.

No-secrets rule (AGENTS.md; audit contract): ``metadata`` must never contain
plaintext API keys, Cognito tokens, passwords, or refresh tokens. The model
types ``metadata`` as a JSON-safe mapping so adapters can persist it without
lossy conversion; services must keep sensitive values out of audit payloads.

Model boundaries:

- ``action``/``target_type`` values (e.g. ``api_key.created``) are bounded
  strings; services own the action vocabulary.
- ``target_type``/``target_id`` are optional: not every audited action names a
  distinct target row (e.g. a broad ``authorization.denied``).

Current behavior and invariants: ``docs/architecture.md``."""

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
    """A record of one audited action (domain model contract)."""

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
