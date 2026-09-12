"""Stable error envelope and machine-readable error codes.

Rules (Phase 01 contract):

- ``code`` is the stable, machine-readable half of the contract; ``message``
  is human-readable and may change without notice. Consumers must branch on
  ``code`` only.
- Codes are additive: renaming or removing a value requires a spec revision.
  HTTP status mapping is HTTP-handling work owned by the task-6 exception
  handlers (``app/api``), deliberately not encoded here.
- Error payloads must never echo submitted secret material (API secrets,
  passwords, tokens): :class:`FieldError` intentionally has **no** ``input``
  or ``value`` field, only a field path and a safe message.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ErrorCode(StrEnum):
    """Stable machine-readable error codes for the ``Error`` envelope."""

    VALIDATION_ERROR = "validation_error"
    UNAUTHENTICATED = "unauthenticated"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    INTERNAL_ERROR = "internal_error"


class FieldError(BaseModel):
    """One field-level problem inside an :class:`Error` envelope.

    ``field`` is a dotted path to the offending input (e.g. ``body.name``);
    ``message`` must be safe to log and display (no secret values).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str = Field(min_length=1)
    message: str = Field(min_length=1)


class Error(BaseModel):
    """Top-level error response envelope; field order is the serialized shape.

    The JSON shape ``{"code", "message", "field_errors", "request_id"}`` is
    frozen for Phase 01+; consumers parse it as-is.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    code: ErrorCode
    message: str = Field(min_length=1)
    field_errors: list[FieldError] = Field(default_factory=list)
    request_id: str | None = Field(
        default=None,
        description="Correlation identifier when available; never secret material.",
    )


__all__ = ["Error", "ErrorCode", "FieldError"]
