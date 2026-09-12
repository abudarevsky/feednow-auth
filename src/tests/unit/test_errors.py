"""Unit tests for the error envelope and codes (Phase 01 task 2)."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.models.errors import Error, ErrorCode, FieldError


def _sample() -> Error:
    return Error(
        code=ErrorCode.VALIDATION_ERROR,
        message="Request validation failed",
        field_errors=[FieldError(field="body.name", message="String should have at least 1 char")],
        request_id="req_01JXYZ7K",
    )


def test_error_json_shape_is_stable():
    payload = json.loads(_sample().model_dump_json())
    assert payload == {
        "code": "validation_error",
        "message": "Request validation failed",
        "field_errors": [
            {"field": "body.name", "message": "String should have at least 1 char"},
        ],
        "request_id": "req_01JXYZ7K",
    }
    # Key order is part of the frozen shape.
    assert list(payload) == ["code", "message", "field_errors", "request_id"]
    assert list(payload["field_errors"][0]) == ["field", "message"]


def test_error_defaults():
    error = Error(code=ErrorCode.NOT_FOUND, message="Organization not found")
    assert error.field_errors == []
    assert error.request_id is None


def test_codes_are_stable_machine_readable_values():
    assert {code.value for code in ErrorCode} == {
        "validation_error",
        "unauthenticated",
        "forbidden",
        "not_found",
        "conflict",
        "internal_error",
    }


def test_unknown_code_rejected():
    with pytest.raises(ValidationError):
        Error(code="something_new", message="x")


def test_field_error_requires_field_and_message():
    with pytest.raises(ValidationError):
        FieldError(field="body.name")
    with pytest.raises(ValidationError):
        FieldError(message="missing field path")
    with pytest.raises(ValidationError):
        FieldError(field="", message="empty path")


def test_envelope_rejects_unknown_fields_and_is_frozen():
    with pytest.raises(ValidationError):
        Error(code=ErrorCode.CONFLICT, message="dup", stack_trace="secret internals")
    with pytest.raises(ValidationError):
        FieldError(field="body.key", message="ok", input="fn_live_01JXYZ7K_a8f...")
    error = _sample()
    with pytest.raises(ValidationError):
        error.message = "mutated"


def test_error_serializes_code_as_plain_string():
    payload = json.loads(Error(code=ErrorCode.CONFLICT, message="dup").model_dump_json())
    assert payload["code"] == "conflict"
    assert type(payload["code"]) is str
