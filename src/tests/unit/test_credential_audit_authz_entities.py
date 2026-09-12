"""Unit tests for credential, audit, and authorization entities: ApiKey,
Scope, AuditEvent, AuthorizationContext (Phase 01 task 4).

Covers the task-4 verify list: §4/§10 field-list equality, ``secret``
rejected via ``extra="forbid"`` with secret-name introspection (only
``secret_hash`` may match), Scope acceptance of every §9 example and
rejection of 2-/4-segment, uppercase, and empty-segment shapes, and
``actor_id``/``organization_id`` typed as the task-2 ID value objects.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter, ValidationError

from app.models import (
    ApiKey,
    AuditEvent,
    AuthorizationContext,
    Scope,
)
from app.models.api_key import SCOPE_PATTERN
from app.models.ids import ApiKeyId, OrganizationId, RecordId, UserId

# --- §4/§10 field lists, verbatim and in spec order ---------------------------

SPEC_FIELD_LISTS = {
    ApiKey: [
        "id",
        "organization_id",
        "created_by_user_id",
        "name",
        "key_id",
        "key_prefix",
        "secret_hash",
        "environment",
        "scopes",
        "status",
        "created_at",
        "last_used_at",
        "expires_at",
        "revoked_at",
    ],
    AuditEvent: [
        "id",
        "organization_id",
        "actor_type",
        "actor_id",
        "action",
        "target_type",
        "target_id",
        "metadata",
        "created_at",
    ],
    AuthorizationContext: ["actor_type", "actor_id", "organization_id", "roles", "scopes"],
}

CREATED = "2026-09-12T10:00:00Z"
EXPIRES = "2027-09-12T00:00:00Z"
SECRET_HASH = "6f7c8b9d0e2a4f6183c5d7e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3"

VALID_PAYLOADS = {
    ApiKey: {
        "id": "key_01JXYZ7K",
        "organization_id": "org_01JXYZ7K",
        "created_by_user_id": "usr_01JXYZ7K",
        "name": "CI pipeline",
        "key_id": "01JXYZ7K",
        "key_prefix": "a8f3c2",
        "secret_hash": SECRET_HASH,
        "environment": "live",
        "scopes": ["vispector:inspection:run", "vispector:project:read"],
        "status": "active",
        "created_at": CREATED,
        "last_used_at": None,
        "expires_at": EXPIRES,
        "revoked_at": None,
    },
    AuditEvent: {
        "id": "aud_01JXYZ7K",
        "organization_id": "org_01JXYZ7K",
        "actor_type": "user",
        "actor_id": "usr_01JXYZ7K",
        "action": "api_key.created",
        "target_type": "api_key",
        "target_id": "key_01JXYZ7K",
        "metadata": {
            "name": "CI pipeline",
            "environment": "live",
            "scopes": ["vispector:inspection:run"],
        },
        "created_at": CREATED,
    },
    AuthorizationContext: {
        "actor_type": "user",
        "actor_id": "usr_01JXYZ7K",
        "organization_id": "org_01JXYZ7K",
        "roles": ["admin"],
        "scopes": [],
    },
}

ALL_MODELS = list(VALID_PAYLOADS)

#: §10's two examples, shapes verbatim (IDs swapped for valid concrete ones).
SPEC_10_HUMAN = {
    "actor_type": "user",
    "actor_id": "usr_01JXYZ7K",
    "organization_id": "org_01JXYZ7K",
    "roles": ["admin"],
    "scopes": [],
}
SPEC_10_API_CLIENT = {
    "actor_type": "api_key",
    "actor_id": "key_01JXYZ7K",
    "organization_id": "org_01JXYZ7K",
    "roles": [],
    "scopes": ["vispector:inspection:run"],
}


def build(model: type, **overrides: object):
    payload = {**VALID_PAYLOADS[model], **overrides}
    return model.model_validate(payload)


# --- §4/§10 field-list equality ------------------------------------------------


@pytest.mark.parametrize("model", ALL_MODELS)
def test_field_list_equals_spec(model):
    assert list(model.model_fields) == SPEC_FIELD_LISTS[model]


# --- no plaintext secret anywhere on ApiKey -------------------------------------


@pytest.mark.parametrize("extra_field", ["secret", "plaintext_secret", "api_secret", "token"])
def test_secret_like_extra_field_rejected_via_forbid(extra_field):
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        build(ApiKey, **{extra_field: "a8f-super-secret-value"})


@pytest.mark.parametrize("model", ALL_MODELS)
def test_only_secret_hash_matches_secret_name_patterns(model):
    secretish = re.compile(r"(secret|token|passw|plaintext|credential)", re.IGNORECASE)
    matches = {name for name in model.model_fields if secretish.search(name)}
    allowed = {"secret_hash"} if model is ApiKey else set()
    assert matches == allowed


# --- Scope value type (spec §9) --------------------------------------------------

SCOPE_ADAPTER = TypeAdapter(Scope)

#: Every scope example from spec §9 (Vispector + future ExcelToPIM).
SPEC_9_EXAMPLES = [
    "vispector:inspection:run",
    "vispector:inspection:read",
    "vispector:project:read",
    "vispector:spec:read",
    "exceltopim:catalog:read",
    "exceltopim:catalog:write",
]

INVALID_SCOPES = [
    pytest.param("vispector:inspection", id="two-segments"),
    pytest.param("vispector:inspection:run:force", id="four-segments"),
    pytest.param("Vispector:inspection:run", id="uppercase-product"),
    pytest.param("vispector:Inspection:run", id="uppercase-resource"),
    pytest.param("vispector:inspection:Run", id="uppercase-action"),
    pytest.param("vispector::run", id="empty-middle-segment"),
    pytest.param(":vispector:inspection:run", id="empty-first-segment"),
    pytest.param("vispector:inspection:", id="empty-last-segment"),
    pytest.param("1vispector:inspection:run", id="digit-leading-segment"),
    pytest.param("vispector_x:inspection:run", id="underscore-in-segment"),
    pytest.param("", id="empty-string"),
    pytest.param("vispector:inspection:" + "r" * 300, id="over-max-length"),
]


@pytest.mark.parametrize("scope", SPEC_9_EXAMPLES)
def test_scope_accepts_every_spec_9_example(scope):
    assert SCOPE_ADAPTER.validate_python(scope) == scope
    assert build(ApiKey, scopes=[scope]).scopes == [scope]


@pytest.mark.parametrize("scope", INVALID_SCOPES)
def test_scope_rejects_invalid_shapes(scope):
    with pytest.raises(ValidationError):
        SCOPE_ADAPTER.validate_python(scope)


@pytest.mark.parametrize("scope", INVALID_SCOPES)
def test_invalid_scope_rejected_inside_api_key(scope):
    with pytest.raises(ValidationError):
        build(ApiKey, scopes=[scope])


def test_scope_pattern_is_single_source():
    # The regex lives only on the Scope type; the pattern constant is the one
    # source task-5 API schemas will reuse (asserted here to pin the shape).
    assert SCOPE_PATTERN == r"^[a-z][a-z0-9]*(:[a-z][a-z0-9]*){2}$"
    assert SCOPE_ADAPTER.json_schema()["pattern"] == SCOPE_PATTERN


# --- extra="forbid" and required fields -------------------------------------------


@pytest.mark.parametrize("model", ALL_MODELS)
def test_extra_fields_forbidden(model):
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        build(model, phone_number="+1-555-0100")


@pytest.mark.parametrize("model", ALL_MODELS)
def test_required_fields_rejected_when_missing(model):
    required = [name for name, f in model.model_fields.items() if f.is_required()]
    for field in required:
        payload = dict(VALID_PAYLOADS[model])
        del payload[field]
        with pytest.raises(ValidationError):
            model.model_validate(payload)


def test_api_key_optional_timestamps_default_to_none():
    payload = {k: v for k, v in VALID_PAYLOADS[ApiKey].items() if not k.endswith("_at")}
    payload["created_at"] = CREATED
    key = ApiKey.model_validate(payload)
    assert key.last_used_at is None
    assert key.expires_at is None
    assert key.revoked_at is None


def test_api_key_optional_timestamps_accept_utc_values():
    key = build(ApiKey, last_used_at=EXPIRES, revoked_at=EXPIRES)
    assert key.last_used_at is not None and key.last_used_at.year == 2027
    assert key.revoked_at is not None


# --- round-trip serialization -------------------------------------------------------


@pytest.mark.parametrize("model", ALL_MODELS)
def test_json_round_trip(model):
    instance = build(model)
    dumped = instance.model_dump_json()
    assert model.model_validate_json(dumped) == instance
    assert model.model_validate(instance.model_dump()) == instance


@pytest.mark.parametrize("model", ALL_MODELS)
def test_canonical_scalar_serialization(model):
    payload = json.loads(build(model).model_dump_json())
    for field_name, value in payload.items():
        if field_name.endswith("_at") and value is not None:
            assert isinstance(value, str) and value.endswith("Z"), field_name
        if field_name in {"status", "environment", "actor_type"}:
            assert isinstance(value, str) and value == value.lower(), field_name
        if field_name in {"id", "organization_id", "actor_id", "created_by_user_id"}:
            assert isinstance(value, str), field_name  # IDs serialize as plain strings


def test_timestamps_serialized_as_utc_including_offset_inputs():
    key = build(ApiKey, created_at="2026-09-12T12:00:00+02:00")
    payload = json.loads(key.model_dump_json())
    assert payload["created_at"] == "2026-09-12T10:00:00Z"


@pytest.mark.parametrize("model", ALL_MODELS)
def test_naive_datetime_rejected(model):
    ts_fields = [name for name in SPEC_FIELD_LISTS[model] if name.endswith("_at")]
    for field in ts_fields:
        with pytest.raises(ValidationError):
            build(model, **{field: "2026-09-12T10:00:00"})


# --- unknown enum strings rejected ----------------------------------------------------


@pytest.mark.parametrize(
    ("model", "field"),
    [
        (ApiKey, "environment"),
        (ApiKey, "status"),
        (AuditEvent, "actor_type"),
        (AuthorizationContext, "actor_type"),
    ],
)
def test_unknown_enum_string_rejected(model, field):
    for bad in ("expired", "pending", "system", "USER", "sandbox", ""):
        with pytest.raises(ValidationError):
            build(model, **{field: bad})


def test_api_key_status_has_no_stored_expiry():
    # Expiry is derived from expires_at (pinned decision), never a status value.
    assert build(ApiKey, status="revoked").status == "revoked"
    with pytest.raises(ValidationError):
        build(ApiKey, status="expired")


@pytest.mark.parametrize("role", ["superuser", "ADMIN", "", "owner "])
def test_invalid_membership_role_rejected(role):
    with pytest.raises(ValidationError):
        build(AuthorizationContext, roles=[role])


# --- actor_id / organization_id are task-2 ID value objects ------------------------------


def test_api_key_ids_are_typed_value_objects():
    key = build(ApiKey)
    assert isinstance(key.id, ApiKeyId)
    assert isinstance(key.organization_id, OrganizationId)
    assert isinstance(key.created_by_user_id, UserId)


@pytest.mark.parametrize("model", [AuditEvent, AuthorizationContext])
def test_actor_and_org_ids_are_typed_value_objects(model):
    instance = build(model)
    assert isinstance(instance.actor_id, (UserId, ApiKeyId))
    assert isinstance(instance.organization_id, OrganizationId)


def test_actor_id_serializes_as_plain_string():
    payload = json.loads(build(AuthorizationContext).model_dump_json())
    assert payload["actor_id"] == "usr_01JXYZ7K"
    assert type(payload["actor_id"]) is str


@pytest.mark.parametrize("model", [AuditEvent, AuthorizationContext])
@pytest.mark.parametrize(
    "bad_actor_id",
    [
        "aud_01JXYZ7K",  # record IDs are never actors
        "extid_01JXYZ7K",
        "mem_01JXYZ7K",
        "usr_...",  # provider-subject-shaped junk
        "11111111-2222-3333-4444-555555555555",  # raw Cognito sub
        "ada@example.com",  # email is never an identity
        "org_01JXYZ7K",  # wrong internal prefix
    ],
)
def test_invalid_actor_id_rejected(model, bad_actor_id):
    with pytest.raises(ValidationError):
        build(model, actor_id=bad_actor_id)


@pytest.mark.parametrize("model", [AuditEvent, AuthorizationContext])
@pytest.mark.parametrize("bad_org_id", ["usr_01JXYZ7K", "key_01JXYZ7K", "aud_01JXYZ7K"])
def test_invalid_organization_id_rejected(model, bad_org_id):
    with pytest.raises(ValidationError):
        build(model, organization_id=bad_org_id)


def test_record_id_base_is_not_an_actor_type():
    # Defense in depth: ActorId is exactly UserId | ApiKeyId.
    assert not issubclass(UserId, RecordId)
    assert not issubclass(ApiKeyId, RecordId)


# --- §10 actor_type / actor_id consistency rule -------------------------------------


@pytest.mark.parametrize(
    ("actor_type", "actor_id"),
    [("user", "key_01JXYZ7K"), ("api_key", "usr_01JXYZ7K")],
)
@pytest.mark.parametrize("model", [AuditEvent, AuthorizationContext])
def test_mismatched_actor_type_and_id_rejected(model, actor_type, actor_id):
    with pytest.raises(ValidationError, match="actor_type"):
        build(model, actor_type=actor_type, actor_id=actor_id)


def test_spec_10_examples_validate():
    human = AuthorizationContext.model_validate(SPEC_10_HUMAN)
    client = AuthorizationContext.model_validate(SPEC_10_API_CLIENT)
    assert isinstance(human.actor_id, UserId) and human.roles == ["admin"] and human.scopes == []
    assert isinstance(client.actor_id, ApiKeyId)
    assert client.roles == [] and client.scopes == ["vispector:inspection:run"]


def test_api_key_actor_round_trips_through_audit_event():
    event = build(
        AuditEvent,
        actor_type="api_key",
        actor_id="key_01JXYZ7K",
        action="authorization.denied",
    )
    assert AuditEvent.model_validate_json(event.model_dump_json()) == event
    assert isinstance(event.actor_id, ApiKeyId)


# --- AuditEvent metadata is a JSON-safe mapping ---------------------------------------


def test_metadata_defaults_to_empty_mapping():
    payload = {k: v for k, v in VALID_PAYLOADS[AuditEvent].items() if k != "metadata"}
    assert AuditEvent.model_validate(payload).metadata == {}


def test_metadata_accepts_nested_json():
    meta = {
        "reason": "missing scope",
        "attempted": "vispector:spec:read",
        "attempts": 3,
        "dry_run": False,
        "tags": ["ci", None, 7],
        "context": {"nested": {"deep": True}},
    }
    event = build(AuditEvent, metadata=meta)
    assert event.metadata == meta
    assert json.loads(event.model_dump_json())["metadata"] == meta


@pytest.mark.parametrize(
    "bad_metadata",
    [
        "not-a-mapping",
        ["list", "not", "allowed"],
        {"when": datetime.now(UTC)},  # non-JSON value type
        {"targets": {1, 2}},  # set is not JSON
    ],
)
def test_metadata_rejects_non_json(bad_metadata):
    with pytest.raises(ValidationError):
        build(AuditEvent, metadata=bad_metadata)


# --- bounded credential strings ----------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("name", ""),
        ("name", "x" * 256),
        ("key_id", ""),
        ("key_id", "x" * 65),
        ("key_prefix", ""),
        ("key_prefix", "x" * 65),
        ("secret_hash", ""),
        ("secret_hash", "x" * 513),
    ],
)
def test_api_key_bounded_text_fields_reject_empty_and_oversized(field, value):
    with pytest.raises(ValidationError):
        build(ApiKey, **{field: value})


@pytest.mark.parametrize(
    ("field", "limit"),
    [("name", 255), ("key_id", 64), ("key_prefix", 64), ("secret_hash", 512)],
)
def test_api_key_bounded_text_at_max_accepted(field, limit):
    assert build(ApiKey, **{field: "x" * limit})


@pytest.mark.parametrize("field", ["action"])
@pytest.mark.parametrize("value", ["", "x" * 129])
def test_audit_action_bounds(field, value):
    with pytest.raises(ValidationError):
        build(AuditEvent, **{field: value})


def test_audit_target_fields_optional():
    event = build(AuditEvent, target_type=None, target_id=None)
    assert event.target_type is None and event.target_id is None
    payload = json.loads(event.model_dump_json())
    assert payload["target_type"] is None and payload["target_id"] is None
