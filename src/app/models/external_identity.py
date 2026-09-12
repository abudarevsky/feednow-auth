"""``ExternalIdentity`` domain entity (spec §4).

Links one provider-side identity to an internal :class:`~app.models.user.User`.
The provider subject (Cognito ``sub``, Shopify ID, ...) is a plain constrained
string (:data:`~app.models.ids.ProviderSubject`) and is never coerced into, or
confused with, the ``usr_`` application identity.

Uniqueness note (spec §4): the tuple ``(provider, provider_subject,
provider_tenant)`` is unique. **Enforcement is Phase 02 storage work** (a
unique index / conditional write), not a Phase 01 model constraint — this
model deliberately performs no cross-row validation.

``provider_tenant`` is optional: providers without a tenant dimension (e.g.
``cognito``) carry ``None``; Shopify will carry the shop domain. How ``None``
participates in the unique index (NULL vs. normalized empty string) is a
Phase 02 storage-contract decision and is carried into the task-7 handoff as
a spec-revision item.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from app.models.enums import IdentityProvider
from app.models.ids import ExternalIdentityId, ProviderSubject, UserId
from app.models.timestamps import UtcDatetime

#: Optional provider-side tenant scope (e.g. a Shopify shop domain).
ProviderTenant = Annotated[str, StringConstraints(min_length=1, max_length=255)]


class ExternalIdentity(BaseModel):
    """One external provider identity attached to a FeedNow user."""

    model_config = ConfigDict(extra="forbid")

    id: ExternalIdentityId
    user_id: UserId
    provider: IdentityProvider
    provider_subject: ProviderSubject
    provider_tenant: ProviderTenant | None = None
    created_at: UtcDatetime


__all__ = ["ExternalIdentity", "ProviderTenant"]
