"""Cursor pagination conventions shared by list endpoints and storage.

Rules (Phase 01 contract):

- Pagination is cursor-based. A cursor is an **opaque** string: only storage
  adapters generate or decode its content, and no application layer may
  parse, construct, or depend on it (AGENTS.md: pagination tokens never leak
  above an adapter).
- Page size is bounded: the default and maximum are pinned here and are the
  single source of truth for API schemas (task 5) and adapters (Phase 02).
- Request-side limits are **clamped** into range rather than rejected, so an
  over-large ``limit`` degrades gracefully to ``MAX_PAGE_LIMIT``.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

#: Default page size when the caller does not request one.
DEFAULT_PAGE_LIMIT = 20

#: Smallest permitted page size.
MIN_PAGE_LIMIT = 1

#: Largest permitted page size; requests above it are clamped.
MAX_PAGE_LIMIT = 100

#: Generous cap so adapter-encoded tokens fit without reinterpretation.
MAX_CURSOR_LENGTH = 2048

#: An opaque, non-empty cursor token. Contents are adapter-defined; nothing
#: outside ``app/storage`` may interpret them.
Cursor = Annotated[str, StringConstraints(min_length=1, max_length=MAX_CURSOR_LENGTH)]


def clamp_limit(value: int) -> int:
    """Clamp a requested page size into ``[MIN_PAGE_LIMIT, MAX_PAGE_LIMIT]``."""
    return max(MIN_PAGE_LIMIT, min(value, MAX_PAGE_LIMIT))


class PageParams(BaseModel):
    """Validated pagination query for list endpoints.

    ``limit`` outside the allowed range is clamped (never a 422); the
    resulting value is always within ``[MIN_PAGE_LIMIT, MAX_PAGE_LIMIT]``.
    """

    model_config = ConfigDict(extra="forbid")

    limit: int = Field(
        default=DEFAULT_PAGE_LIMIT,
        ge=MIN_PAGE_LIMIT,
        le=MAX_PAGE_LIMIT,
        description="Requested page size; out-of-range values are clamped.",
    )
    cursor: Cursor | None = Field(
        default=None,
        description="Opaque continuation token from a previous Page; adapter-defined.",
    )

    @field_validator("limit", mode="before")
    @classmethod
    def _clamp_limit(cls, value: object) -> object:
        # HTTP query parameters arrive as strings, so numeric strings are
        # coerced before clamping; that is the whole point of the clamp rule.
        # Anything non-numeric falls through to regular int validation so
        # malformed input still errors.
        if isinstance(value, bool):
            raise ValueError("limit must be an integer, not a boolean")
        if isinstance(value, int):
            return clamp_limit(value)
        if isinstance(value, str):
            try:
                return clamp_limit(int(value.strip()))
            except ValueError:
                return value
        return value


class Page[T](BaseModel):
    """One page of results plus an optional opaque continuation cursor.

    ``items`` are domain or schema objects; ``next_cursor`` is ``None`` on
    the final page. ``limit`` echoes the effective page size and is expected
    to come from an already-validated :class:`PageParams` (a value outside
    the bounds is a programming error and fails validation here).
    """

    model_config = ConfigDict(extra="forbid")

    items: list[T] = Field(default_factory=list)
    limit: int = Field(
        default=DEFAULT_PAGE_LIMIT,
        ge=MIN_PAGE_LIMIT,
        le=MAX_PAGE_LIMIT,
        description="Effective page size used to produce this page.",
    )
    next_cursor: Cursor | None = Field(
        default=None,
        description="Opaque cursor for the next page; None means no more pages.",
    )


__all__ = [
    "DEFAULT_PAGE_LIMIT",
    "MAX_CURSOR_LENGTH",
    "MAX_PAGE_LIMIT",
    "MIN_PAGE_LIMIT",
    "Cursor",
    "Page",
    "PageParams",
    "clamp_limit",
]
