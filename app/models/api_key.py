"""``ApiKey`` credential entity and ``Scope`` value type (spec §4, §8, §9).

The field list is exactly the §4 list — no more, no fewer. Among
secret-bearing fields **only** ``secret_hash`` exists: the plaintext secret is
returned once at creation (spec §15) and must never be persisted or logged
(AGENTS.md). ``secret_hash`` holds the HMAC-SHA256 digest (spec §8), not the
secret itself.

Deliberate Phase 01 boundaries:

- ``key_id`` is the non-secret credential segment inside
  ``fn_live_<key-id>_<secret>`` (spec §8). Its format (ULID-style entropy) and
  ``key_prefix`` display length are owned by Phase 05; both are bounded plain
  strings here. ``key_id`` is distinct from the ``key_`` application identity
  :class:`~app.models.ids.ApiKeyId` (``ApiKey.id``).
- ``status`` never stores an "expired" value: expiry is **derived** from
  ``expires_at`` at verification time (pinned ``ApiKeyStatus`` decision).
- Scope *semantics* (no commercial plans or rate-limit policy in scopes) are a
  design/review rule (AGENTS.md), not a runtime denylist; this module only
  validates the §9 shape.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from app.models.enums import ApiKeyEnvironment, ApiKeyStatus
from app.models.ids import ApiKeyId, OrganizationId, UserId
from app.models.timestamps import UtcDatetime

#: Single source of the scope shape: exactly three lowercase
#: ``product:resource:action`` segments (spec §9; all §9 examples match).
#: API schemas (task 5) reuse :data:`Scope` — the pattern is never duplicated.
SCOPE_PATTERN = r"^[a-z][a-z0-9]*(:[a-z][a-z0-9]*){2}$"

#: One validated product scope, e.g. ``vispector:inspection:run``.
Scope = Annotated[str, StringConstraints(pattern=SCOPE_PATTERN, max_length=255)]

#: Bounded human-readable key label.
ApiKeyName = Annotated[str, StringConstraints(min_length=1, max_length=255)]

#: Non-secret ``<key-id>`` segment of the credential literal (spec §8);
#: format owned by Phase 05 — bounded string only.
KeyId = Annotated[str, StringConstraints(min_length=1, max_length=64)]

#: Non-secret display prefix used for key identification in listings; the
#: exact truncation rule is Phase 05 work — bounded string only.
KeyPrefix = Annotated[str, StringConstraints(min_length=1, max_length=64)]

#: Stored HMAC-SHA256 digest of the secret (spec §8). Encoding (hex/base64) is
#: Phase 05 work; the bound is generous for either. This is the only field
#: derived from secret material, and it is never the plaintext secret.
SecretHash = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class ApiKey(BaseModel):
    """A first-class FeedNow API-key credential row (spec §4)."""

    model_config = ConfigDict(extra="forbid")

    id: ApiKeyId
    organization_id: OrganizationId
    created_by_user_id: UserId
    name: ApiKeyName
    key_id: KeyId
    key_prefix: KeyPrefix
    secret_hash: SecretHash
    environment: ApiKeyEnvironment
    scopes: list[Scope]
    status: ApiKeyStatus
    created_at: UtcDatetime
    last_used_at: UtcDatetime | None = None
    expires_at: UtcDatetime | None = None
    revoked_at: UtcDatetime | None = None


__all__ = [
    "SCOPE_PATTERN",
    "ApiKey",
    "ApiKeyName",
    "KeyId",
    "KeyPrefix",
    "Scope",
    "SecretHash",
]
