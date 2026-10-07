"""Local platform administration request and response schemas."""

from typing import Annotated

from pydantic import StringConstraints

from app.api.schemas.common import ApiSchema
from app.models.enums import MembershipRole, MembershipStatus, UserStatus
from app.models.ids import OrganizationId, UserId
from app.models.pagination import PageParams
from app.models.timestamps import UtcDatetime
from app.models.user import Email, Username


class AdminSummary(ApiSchema):
    organization_count: int
    active_membership_count: int


class AdminOrganizationQuery(PageParams):
    q: str = ""


class AdminMember(ApiSchema):
    user_id: UserId
    display_name: str
    username: Username | None = None
    email: Email | None = None
    account_status: UserStatus
    membership_status: MembershipStatus
    role: MembershipRole
    registered_at: UtcDatetime
    joined_at: UtcDatetime


class AdminOrganization(ApiSchema):
    id: OrganizationId
    name: str
    slug: str
    type: str
    name_status: str
    status: str
    enabled: bool = True
    suspended_at: UtcDatetime | None = None
    created_at: UtcDatetime
    member_count: int
    members: list[AdminMember]
    is_current_user_owner: bool


class AdminOrganizationDetail(AdminOrganization):
    updated_at: UtcDatetime
    services: list[dict[str, str]]
    api_keys: list[dict[str, object]]


class AdminOrganizationStateRequest(ApiSchema):
    """Empty body required by the versioned POST enable/disable actions."""

    pass


class AdminSuspendRequest(ApiSchema):
    confirmation: Annotated[str, StringConstraints(pattern="^SUSPEND$")]


class AdminReactivateRequest(ApiSchema):
    confirmation: Annotated[str, StringConstraints(pattern="^REACTIVATE$")]


class AdminDeleteRequest(ApiSchema):
    organization_name: Annotated[str, StringConstraints(min_length=1, max_length=255)]


__all__ = [
    "AdminMember",
    "AdminOrganization",
    "AdminOrganizationDetail",
    "AdminOrganizationQuery",
    "AdminOrganizationStateRequest",
    "AdminReactivateRequest",
    "AdminSummary",
]
