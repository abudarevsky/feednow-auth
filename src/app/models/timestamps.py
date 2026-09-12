"""UTC-only datetime conventions for domain models and API payloads.

Rules (Phase 01 contract, per spec and AGENTS.md):

- Models reject naive datetimes on input; every stored/transmitted instant is
  timezone-aware and normalized to UTC.
- JSON serialization is canonical UTC ISO-8601 / RFC 3339 with a ``Z`` suffix
  (e.g. ``2026-09-12T10:00:00Z``) so SQLite and DynamoDB round-trips stay
  comparable across adapters.
- Python-mode dumps keep real :class:`~datetime.datetime` objects so storage
  adapters can compare them without reparsing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator, PlainSerializer, WithJsonSchema


def utc_now() -> datetime:
    """Current time as a timezone-aware UTC datetime (service clock source)."""
    return datetime.now(UTC)


def ensure_utc(value: datetime) -> datetime:
    """Reject naive datetimes and normalize aware ones to UTC.

    Raises:
        ValueError: if ``value`` is naive (no UTC offset information).
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("naive datetimes are not allowed; supply a UTC-aware datetime")
    return value.astimezone(UTC)


def to_utc_rfc3339(value: datetime) -> str:
    """Serialize a datetime as canonical UTC ISO-8601 with a ``Z`` suffix."""
    normalized = ensure_utc(value)
    return normalized.isoformat().replace("+00:00", "Z")


#: Annotated datetime enforcing the reject-naive rule on input and the
#: UTC ``Z`` serialization rule on JSON output. Use for every timestamp
#: field in Phase 01+ models; optional timestamps are ``UtcDatetime | None``.
UtcDatetime = Annotated[
    datetime,
    AfterValidator(ensure_utc),
    PlainSerializer(to_utc_rfc3339, when_used="json"),
    WithJsonSchema({"type": "string", "format": "date-time"}),
]

__all__ = ["UtcDatetime", "ensure_utc", "to_utc_rfc3339", "utc_now"]
