"""Registered product services and single-use authorization codes.

Service configuration contains only public routing policy and a reference to
the operator-managed server credential. Authorization codes are persisted as
digests; their plaintext value exists only in the handoff response.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from app.models.ids import OrganizationId, UserId
from app.models.timestamps import UtcDatetime

ServiceId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9-]{0,62}$")]
ServicePermission = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9:_-]{0,63}$")]
AuthorizationCodeDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
ServiceCredentialReference = Annotated[str, StringConstraints(min_length=1, max_length=255)]


class ServiceRegistration(BaseModel):
    """Operator-defined routing and permission policy for one product service."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    service_id: ServiceId
    display_name: Annotated[str, StringConstraints(min_length=1, max_length=100)]
    allowed_origins: tuple[
        Annotated[str, StringConstraints(min_length=1, max_length=2048)], ...
    ] = Field(min_length=1)
    callback_path: Annotated[str, StringConstraints(pattern=r"^/[A-Za-z0-9/_-]*$")]
    enabled: bool
    allowed_permissions: tuple[ServicePermission, ...] = Field(min_length=1)
    credential_reference: ServiceCredentialReference

    @field_validator("allowed_origins", "allowed_permissions")
    @classmethod
    def _unique_values(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("values must be unique")
        return values

    @field_validator("allowed_origins")
    @classmethod
    def _absolute_origins(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        from urllib.parse import urlsplit

        for origin in values:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError(
                    "origins must be absolute HTTP origins without credentials or paths"
                )
        return values


class ServiceAuthorizationCode(BaseModel):
    """Hashed handoff code and the authorization snapshot issued to a service."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    code_digest: AuthorizationCodeDigest
    service_id: ServiceId
    user_id: UserId
    organization_id: OrganizationId
    permissions: tuple[ServicePermission, ...] = Field(min_length=1)
    permission_version: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    expires_at: UtcDatetime
    consumed_at: UtcDatetime | None = None

    @field_validator("permissions")
    @classmethod
    def _unique_permissions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("permissions must be unique")
        return values


__all__ = [
    "AuthorizationCodeDigest",
    "ServiceAuthorizationCode",
    "ServiceCredentialReference",
    "ServiceId",
    "ServicePermission",
    "ServiceRegistration",
]
