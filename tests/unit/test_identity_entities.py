"""Unit tests for identity entities: User, ExternalIdentity, Organization,
Membership (Phase 01 task 3).

Covers the task-3 verify list: round-trip serialization, unknown enum-string
rejection, ``extra="forbid"``, ``User.id`` (``usr_``) distinct from
``ExternalIdentity.provider_subject``, and §4 field-list equality per entity.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.models import (
    ExternalIdentity,
    Membership,
    Organization,
    User,
)
from app.models.ids import UserId

# --- §4 field lists, verbatim and in spec order -----------------------------

SPEC_FIELD_LISTS = {
    User: ["id", "display_name", "email", "status", "created_at", "updated_at"],
    ExternalIdentity: [
        "id",
        "user_id",
        "provider",
        "provider_subject",
        "provider_tenant",
        "created_at",
    ],
    Organization: [
        "id",
        "name",
        "slug",
        "type",
        "status",
        "created_at",
        "updated_at",
    ],
    Membership: [
        "id",
        "organization_id",
        "user_id",
        "role",
        "status",
        "created_at",
    ],
}

CREATED = "2026-09-12T10:00:00Z"
UPDATED = "2026-09-12T11:30:00Z"

VALID_PAYLOADS = {
    User: {
        "id": "usr_01JXYZ7K",
        "display_name": "Ada Liddell",
        "email": "ada@example.com",
        "status": "active",
        "created_at": CREATED,
        "updated_at": UPDATED,
    },
    ExternalIdentity: {
        "id": "extid_01JXYZ7K",
        "user_id": "usr_01JXYZ7K",
        "provider": "cognito",
        "provider_subject": "11111111-2222-3333-4444-555555555555",
        "created_at": CREATED,
    },
    Organization: {
        "id": "org_01JXYZ7K",
        "name": "Acme Feed Co.",
        "slug": "acme-feed",
        "type": "customer",
        "status": "active",
        "created_at": CREATED,
        "updated_at": UPDATED,
    },
    Membership: {
        "id": "mem_01JXYZ7K",
        "organization_id": "org_01JXYZ7K",
        "user_id": "usr_01JXYZ7K",
        "role": "admin",
        "status": "active",
        "created_at": CREATED,
    },
}

ALL_ENTITIES = list(VALID_PAYLOADS)


def build(entity: type, **overrides: object):
    payload = {**VALID_PAYLOADS[entity], **overrides}
    return entity.model_validate(payload)


# --- §4 field-list equality --------------------------------------------------


@pytest.mark.parametrize("entity", ALL_ENTITIES)
def test_field_list_equals_spec_section_4(entity):
    assert list(entity.model_fields) == SPEC_FIELD_LISTS[entity]


# --- extra="forbid" ----------------------------------------------------------


@pytest.mark.parametrize("entity", ALL_ENTITIES)
def test_extra_fields_forbidden(entity):
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        build(entity, phone_number="+1-555-0100")


# --- round-trip serialization -------------------------------------------------


@pytest.mark.parametrize("entity", ALL_ENTITIES)
def test_json_round_trip(entity):
    model = build(entity)
    dumped = model.model_dump_json()
    assert entity.model_validate_json(dumped) == model
    # Python-mode round trip too (storage adapters hand over dicts).
    assert entity.model_validate(model.model_dump()) == model


@pytest.mark.parametrize("entity", ALL_ENTITIES)
def test_enums_and_timestamps_serialize_as_canonical_strings(entity):
    payload = json.loads(build(entity).model_dump_json())
    for field_name, value in payload.items():
        if field_name.endswith("_at"):
            assert isinstance(value, str) and value.endswith("Z"), field_name
        elif field_name in {"status", "role", "type", "provider"}:
            assert isinstance(value, str) and value == value.lower(), field_name


def test_timestamps_serialized_as_utc_including_offset_inputs():
    model = build(
        User,
        created_at="2026-09-12T12:00:00+02:00",
        updated_at="2026-09-12T10:00:00Z",
    )
    payload = json.loads(model.model_dump_json())
    assert payload["created_at"] == "2026-09-12T10:00:00Z"


@pytest.mark.parametrize("entity", ALL_ENTITIES)
def test_naive_datetime_rejected(entity):
    ts_fields = [name for name in SPEC_FIELD_LISTS[entity] if name.endswith("_at")]
    for field in ts_fields:
        with pytest.raises(ValidationError):
            build(entity, **{field: "2026-09-12T10:00:00"})


# --- unknown enum strings rejected (per entity field) -------------------------

INVALID_ENUM_FIELDS = {
    User: ["status"],
    ExternalIdentity: ["provider"],
    Organization: ["type", "status"],
    Membership: ["role", "status"],
}


@pytest.mark.parametrize(
    ("entity", "field"),
    [(e, f) for e, fields in INVALID_ENUM_FIELDS.items() for f in fields],
)
def test_unknown_enum_string_rejected(entity, field):
    for bad in ("pending", "OWNER", "", "suspended", "unknown"):
        with pytest.raises(ValidationError):
            build(entity, **{field: bad})


@pytest.mark.parametrize(
    ("entity", "field"),
    [(e, f) for e, fields in INVALID_ENUM_FIELDS.items() for f in fields],
)
def test_missing_enum_field_rejected(entity, field):
    payload = dict(VALID_PAYLOADS[entity])
    del payload[field]
    with pytest.raises(ValidationError):
        entity.model_validate(payload)


# --- application identity vs. provider subject --------------------------------


def test_user_id_requires_internal_prefix():
    with pytest.raises(ValidationError, match="must start with 'usr_'"):
        build(User, id="11111111-2222-3333-4444-555555555555")  # raw Cognito sub
    with pytest.raises(ValidationError, match="must start with 'usr_'"):
        build(User, id="shop_123")  # Shopify-flavored ID
    with pytest.raises(ValidationError, match="must start with 'usr_'"):
        build(User, id="ada@example.com")  # email is never an identity
    with pytest.raises(ValidationError, match="must start with 'usr_'"):
        build(User, id="org_01JXYZ7K")  # wrong internal prefix


def test_provider_subject_is_plain_string_never_user_id():
    identity = build(ExternalIdentity)
    assert type(identity.provider_subject) is str
    assert not isinstance(identity.provider_subject, UserId)
    # Even a value that *looks* like an internal ID stays a plain string:
    # the provider column is not coerced into an application identity.
    tricky = build(ExternalIdentity, provider_subject="usr_01JXYZ7K")
    assert type(tricky.provider_subject) is str


def test_external_identity_user_id_is_typed_application_id():
    identity = build(ExternalIdentity)
    assert isinstance(identity.user_id, UserId)
    with pytest.raises(ValidationError, match="must start with 'usr_'"):
        build(ExternalIdentity, user_id="11111111-2222-3333-4444-555555555555")


def test_record_id_prefixes_are_not_application_ids():
    # An ``extid_``/``mem_`` record ID never validates as ``usr_``/``org_``.
    with pytest.raises(ValidationError, match="must start with 'usr_'"):
        build(Membership, user_id="extid_01JXYZ7K")
    with pytest.raises(ValidationError, match="must start with 'org_'"):
        build(Membership, organization_id="mem_01JXYZ7K")
    with pytest.raises(ValidationError, match="must start with 'extid_'"):
        build(ExternalIdentity, id="usr_01JXYZ7K")
    with pytest.raises(ValidationError, match="must start with 'mem_'"):
        build(Membership, id="org_01JXYZ7K")


# --- provider_tenant optionality ----------------------------------------------


def test_provider_tenant_optional_and_defaults_to_none():
    identity = build(ExternalIdentity)
    assert identity.provider_tenant is None
    shop = build(
        ExternalIdentity,
        provider="shopify",
        provider_subject="gid://shopify/Shop/1234",
        provider_tenant="acme.myshopify.com",
    )
    assert shop.provider_tenant == "acme.myshopify.com"
    with pytest.raises(ValidationError):
        build(ExternalIdentity, provider_tenant="")


# --- organization slug / bounded text conventions ------------------------------


@pytest.mark.parametrize("slug", ["acme", "acme-feed", "Acme Feed", "workspace-usr_1"])
def test_slug_is_bounded_free_text(slug):
    # Phase 01 deliberately does not pin a slug format (owner-phase work).
    assert build(Organization, slug=slug).slug == slug


@pytest.mark.parametrize("slug", ["", "x" * 256])
def test_invalid_slugs_rejected(slug):
    with pytest.raises(ValidationError):
        build(Organization, slug=slug)


@pytest.mark.parametrize("name", ["", "x" * 256])
def test_organization_name_bounds(name):
    with pytest.raises(ValidationError):
        build(Organization, name=name)


@pytest.mark.parametrize("field", ["display_name", "email"])
@pytest.mark.parametrize("value", ["", "x" * 321])
def test_user_text_field_bounds(field, value):
    with pytest.raises(ValidationError):
        build(User, **{field: value})


def test_user_display_name_max_below_email_max():
    # 255 cap on display_name, 320 cap on email (documented bounds).
    with pytest.raises(ValidationError):
        build(User, display_name="x" * 256)
    assert build(User, email="x" * 320).email == "x" * 320


def test_empty_provider_subject_rejected():
    with pytest.raises(ValidationError):
        build(ExternalIdentity, provider_subject="")


@pytest.mark.parametrize(
    ("entity", "required_field"),
    [
        (User, "id"),
        (ExternalIdentity, "id"),
        (ExternalIdentity, "user_id"),
        (Organization, "id"),
        (Membership, "id"),
        (Membership, "organization_id"),
        (Membership, "user_id"),
    ],
)
def test_required_fields_rejected_when_missing(entity, required_field):
    payload = dict(VALID_PAYLOADS[entity])
    del payload[required_field]
    with pytest.raises(ValidationError):
        entity.model_validate(payload)
