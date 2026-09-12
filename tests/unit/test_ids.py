"""Unit tests for typed ID value objects (Phase 01 task 2)."""

from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, ValidationError

from app.models.ids import (
    MAX_ID_LENGTH,
    ApiKeyId,
    ApplicationId,
    AuditEventId,
    ExternalIdentityId,
    MembershipId,
    OrganizationId,
    ProviderSubject,
    RecordId,
    UserId,
)

ALL_ID_TYPES = [
    (UserId, "usr"),
    (OrganizationId, "org"),
    (ApiKeyId, "key"),
    (ExternalIdentityId, "extid"),
    (MembershipId, "mem"),
    (AuditEventId, "aud"),
]

APPLICATION_PREFIXES = {"usr", "org", "key"}


class _Holder(BaseModel):
    id: UserId


@pytest.mark.parametrize(("id_type", "prefix"), ALL_ID_TYPES)
def test_accepts_own_prefix(id_type, prefix):
    value = f"{prefix}_01JXYZ7K-a_1"
    ident = id_type(value)
    assert str(ident) == value
    assert isinstance(ident, str)


@pytest.mark.parametrize(("id_type", "prefix"), ALL_ID_TYPES)
def test_wrong_prefix_rejected_per_type(id_type, prefix):
    for other_prefix in {p for _, p in ALL_ID_TYPES} - {prefix}:
        with pytest.raises(ValueError, match="must start with"):
            id_type(f"{other_prefix}_abc")
    # Missing prefix entirely (e.g. a raw Cognito sub or a ULID segment).
    with pytest.raises(ValueError, match="must start with"):
        id_type("01JXYZ7K")
    with pytest.raises(ValueError, match="must start with"):
        id_type(f"{prefix.upper()}_abc")


@pytest.mark.parametrize(("id_type", "prefix"), ALL_ID_TYPES)
def test_model_validation_rejects_wrong_shape(id_type, prefix):
    class Holder(BaseModel):
        id: id_type

    assert Holder(id=f"{prefix}_x1").id == id_type(f"{prefix}_x1")
    with pytest.raises(ValidationError):
        Holder(id=f"{prefix}_")  # empty suffix
    with pytest.raises(ValidationError):
        Holder(id=f"{prefix}_bad suffix")  # whitespace not allowed
    with pytest.raises(ValidationError):
        Holder(id=f"{prefix}_boom!")  # punctuation not allowed
    with pytest.raises(ValidationError):
        Holder(id=f"{prefix}_{'a' * MAX_ID_LENGTH}")  # over length cap
    with pytest.raises(ValidationError):
        Holder(id=123)  # non-string


def test_application_ids_are_distinct_from_record_ids():
    assert issubclass(UserId, ApplicationId)
    assert issubclass(OrganizationId, ApplicationId)
    assert issubclass(ApiKeyId, ApplicationId)
    assert not issubclass(UserId, RecordId)
    for record_type in (ExternalIdentityId, MembershipId, AuditEventId):
        assert issubclass(record_type, RecordId)
        assert not issubclass(record_type, ApplicationId)
    # A record ID is never accepted where an application identity is required.
    with pytest.raises(ValidationError):
        _Holder(id="mem_abc")
    # Cross-type application IDs are also rejected (usr_ where org_ is typed).
    with pytest.raises(ValueError, match="must start with"):
        OrganizationId(str(UserId("usr_abc")))


def test_abstract_bases_cannot_be_constructed():
    with pytest.raises(TypeError):
        ApplicationId("usr_abc")
    with pytest.raises(TypeError):
        RecordId("aud_abc")


def test_provider_subject_is_plain_string_never_coerced_to_user_id():
    cognito_sub = "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"

    class Resolution(BaseModel):
        subject: ProviderSubject
        user_id: UserId

    # The provider subject stays a plain str...
    result = Resolution(subject=cognito_sub, user_id="usr_01JXYZ7K")
    assert type(result.subject) is str
    assert result.subject == cognito_sub
    # ...and is never accepted in the UserId slot (no coercion, wrong prefix).
    with pytest.raises(ValidationError):
        Resolution(subject="usr_01JXYZ7K", user_id=cognito_sub)
    # Email is likewise never a valid user identity.
    with pytest.raises(ValidationError):
        Resolution(subject="a@b.example", user_id="a@b.example")


def test_ids_serialize_as_plain_json_strings():
    holder = _Holder(id="usr_01JXYZ7K")
    payload = json.loads(holder.model_dump_json())
    assert payload == {"id": "usr_01JXYZ7K"}
    assert type(payload["id"]) is str
    # Python-mode dump preserves the value-object type for adapters.
    assert isinstance(holder.model_dump()["id"], UserId)


def test_ids_are_hashable_and_compare_by_value():
    a, b = UserId("usr_abc"), UserId("usr_abc")
    assert a == b
    assert hash(a) == hash(b)
    assert len({a, b}) == 1
    assert UserId(UserId("usr_abc")) == "usr_abc"  # str-subclass equality


def test_json_schema_pins_prefix_pattern():
    schema = _Holder.model_json_schema()
    assert schema["properties"]["id"]["pattern"] == r"^usr_[0-9A-Za-z_-]+$"
    assert schema["properties"]["id"]["type"] == "string"
