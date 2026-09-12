"""Shared building blocks for the versioned HTTP request/response schemas.

Phase 01 contract rules (task 5):

- Every API schema derives from :class:`ApiSchema`, which forbids unknown
  fields (``extra="forbid"``). Response shapes are therefore closed,
  additive-only contracts: a new field is a deliberate contract change, and
  clients never observe undeclared keys.
- Pagination is **re-exported** from :mod:`app.models.pagination` — the
  single source of truth for page bounds and cursor opacity. List endpoints
  accept :class:`~app.models.pagination.PageParams` (``limit`` clamped to
  ``[MIN_PAGE_LIMIT, MAX_PAGE_LIMIT]``, default ``DEFAULT_PAGE_LIMIT``;
  opaque ``cursor``) as query parameters and return
  ``Page[<response model>]``. Nothing above a storage adapter may generate,
  decode, or interpret cursor content (AGENTS.md).
- No module here may carry secret material: the only full-credential type in
  the whole API surface is
  :class:`~app.api.schemas.api_keys.ApiKeyCreatedResponse` (spec §15), and
  it lives in its own module, not in this shared one.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from app.models.pagination import Cursor, Page, PageParams


class ApiSchema(BaseModel):
    """Base for every request/response model in :mod:`app.api.schemas`.

    Unknown fields are rejected so serialized responses stay exactly the
    declared contract; per-model ``extra="forbid"`` assertions in the tests
    enforce that no subclass relaxes it.
    """

    model_config = ConfigDict(extra="forbid")


__all__ = ["ApiSchema", "Cursor", "Page", "PageParams"]
