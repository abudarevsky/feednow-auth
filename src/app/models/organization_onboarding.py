"""Durable, secret-free requests to provision an organization in Vispector."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.models.ids import OrganizationId
from app.models.timestamps import UtcDatetime

OnboardingRequestId = Annotated[str, StringConstraints(pattern=r"^onb_[0-9a-f]{32}$")]
OnboardingStatus = Literal["pending", "succeeded", "failed"]


class OrganizationOnboardingRequest(BaseModel):
    """Outbox record committed atomically with first user provisioning."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: OnboardingRequestId
    organization_id: OrganizationId
    bootstrap_version: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    status: OnboardingStatus = "pending"
    attempts: Annotated[int, Field(ge=0)] = 0
    created_at: UtcDatetime
    updated_at: UtcDatetime
    last_error: Annotated[str | None, StringConstraints(max_length=120)] = None


__all__ = ["OnboardingRequestId", "OnboardingStatus", "OrganizationOnboardingRequest"]
