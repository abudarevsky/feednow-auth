"""Unit tests for UTC timestamp conventions (Phase 01 task 2)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import BaseModel, ValidationError

from app.models.timestamps import UtcDatetime, ensure_utc, to_utc_rfc3339, utc_now


class _Event(BaseModel):
    occurred_at: UtcDatetime


@pytest.mark.parametrize(
    "naive",
    [
        datetime(2026, 1, 1, 12, 0, 0),
        "2026-01-01T12:00:00",  # offset-less string parses naive
    ],
)
def test_naive_datetime_rejected(naive):
    with pytest.raises(ValidationError, match="naive datetimes are not allowed"):
        _Event(occurred_at=naive)


def test_aware_non_utc_input_is_normalized_to_utc():
    plus_two = timezone(timedelta(hours=2))
    event = _Event(occurred_at=datetime(2026, 1, 1, 12, 0, 0, tzinfo=plus_two))
    assert event.occurred_at == datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
    assert event.occurred_at.utcoffset() == timedelta(0)


def test_json_serialization_is_utc_rfc3339_with_z():
    event = _Event(occurred_at="2026-09-12T12:30:00+02:00")
    payload = json.loads(event.model_dump_json())
    assert payload == {"occurred_at": "2026-09-12T10:30:00Z"}


def test_python_dump_keeps_real_datetime_objects():
    event = _Event(occurred_at="2026-09-12T10:30:00Z")
    dumped = event.model_dump()
    assert isinstance(dumped["occurred_at"], datetime)
    assert dumped["occurred_at"].tzinfo is not None


def test_utc_string_round_trips():
    original = _Event(occurred_at=utc_now())
    wire = original.model_dump_json()
    restored = _Event(**json.loads(wire))
    assert restored.occurred_at == original.occurred_at


def test_json_schema_is_date_time_string():
    schema = _Event.model_json_schema()
    assert schema["properties"]["occurred_at"]["type"] == "string"
    assert schema["properties"]["occurred_at"]["format"] == "date-time"


def test_ensure_utc_helper_directly():
    with pytest.raises(ValueError, match="naive"):
        ensure_utc(datetime(2026, 1, 1, 0, 0, 0))
    aware = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone(timedelta(hours=-5)))
    assert ensure_utc(aware) == datetime(2026, 1, 1, 5, 0, 0, tzinfo=UTC)


def test_to_utc_rfc3339_helper():
    assert to_utc_rfc3339(datetime(2026, 1, 1, 5, 0, 0, tzinfo=UTC)) == "2026-01-01T05:00:00Z"
    with pytest.raises(ValueError, match="naive"):
        to_utc_rfc3339(datetime(2026, 1, 1, 5, 0, 0))


def test_utc_now_is_aware_utc():
    now = utc_now()
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(0)
