"""Schemas for authenticated service-to-service authorization."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.api.schemas.common import ApiSchema
from app.models.ids import ApiKeyId, OrganizationId, UserId


class ApiKeyValidationRequest(ApiSchema):
    """An existing API-key literal submitted by an authenticated service."""

    key: str = Field(min_length=1, max_length=512)


class ApiKeyValidationResponse(ApiSchema):
    """Safe authorization context; never includes key or credential material."""

    actor_type: Literal["api_key"]
    actor_id: ApiKeyId
    user_id: UserId
    organization_id: OrganizationId
    service: Literal["vispector"]
    permissions: list[str]
    expires_at: datetime | None
