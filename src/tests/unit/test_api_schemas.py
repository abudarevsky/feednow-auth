"""Unit tests for the versioned API schemas (Phase 01 task 5).

Covers the task-5 verify list: summary/list models have no secret or hash
fields (field-name introspection + ``extra="forbid"``), unknown response
fields are forbidden, the key-creation request rejects invalid environment
and invalid scope shapes, §15 payloads round-trip verbatim, and list
endpoints return ``Page[...]`` with opaque cursors.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

import app.api.schemas as schemas_package
from app.api.schemas import (
    ApiKeyCreatedResponse,
    ApiKeyCreateRequest,
    ApiKeySummary,
    MemberCreateRequest,
    MemberResponse,
    MeResponse,
    OrganizationCreateRequest,
    OrganizationResponse,
    Page,
    PageParams,
)
from app.api.schemas.manifest import ENDPOINTS
from app.models.user import User

# --- §15 payloads, copied verbatim from the spec ------------------------------

SECTION_15_REQUEST: dict[str, Any] = {
    "name": "Production inspection",
    "environment": "live",
    "scopes": [
        "vispector:inspection:run",
        "vispector:inspection:read",
    ],
}

SECTION_15_RESPONSE: dict[str, Any] = {
    "id": "key_01JXYZ7K",
    "name": "Production inspection",
    "key": "fn_live_01JXYZ7K_a8f3c2d4e5b67189",
    "created_at": "2026-09-12T10:00:00Z",
}

CREATED_AT = "2026-09-12T10:00:00Z"

VALID_SUMMARY: dict[str, Any] = {
    "id": "key_01JXYZ7K",
    "name": "CI pipeline",
    "environment": "test",
    "key_prefix": "fn_test_01JXYZ7K_a8f3",
    "status": "active",
    "scopes": ["vispector:inspection:run"],
    "created_at": CREATED_AT,
    "last_used_at": None,
    "expires_at": None,
    "revoked_at": None,
}

#: Field names that would leak persisted or transport secret material.
SECRET_NAME_RE = re.compile(r"secret|hash|token|password|plaintext", re.IGNORECASE)


def _schema_models() -> list[type[BaseModel]]:
    """Every BaseModel *defined* in the app.api.schemas package modules."""
    models: list[type[BaseModel]] = []
    for module_info in pkgutil.iter_modules(schemas_package.__path__):
        module = importlib.import_module(f"app.api.schemas.{module_info.name}")
        for value in vars(module).values():
            if (
                isinstance(value, type)
                and issubclass(value, BaseModel)
                and value.__module__ == module.__name__
            ):
                models.append(value)
    return models


def _list_models() -> list[type[BaseModel]]:
    """The parameterized ``Page[...]`` response models referenced by the manifest."""
    return [spec.response_model for spec in ENDPOINTS if spec.is_list]


# --- global schema invariants -------------------------------------------------


def test_every_schema_model_forbids_unknown_fields() -> None:
    models = _schema_models() + _list_models()
    assert models, "schemas package must define models"
    for model in models:
        assert model.model_config.get("extra") == "forbid", model


def test_no_schema_model_exposes_secret_material_by_name() -> None:
    for model in _schema_models() + _list_models():
        offenders = [name for name in model.model_fields if SECRET_NAME_RE.search(name)]
        assert not offenders, f"{model.__name__} leaks secret-named fields: {offenders}"


def test_full_key_field_exists_only_on_creation_response() -> None:
    with_key = [model.__name__ for model in _schema_models() if "key" in model.model_fields]
    assert with_key == ["ApiKeyCreatedResponse"]


# --- key creation (spec §15 verbatim) ------------------------------------------


def test_create_request_accepts_section_15_payload_verbatim() -> None:
    parsed = ApiKeyCreateRequest.model_validate(SECTION_15_REQUEST)
    assert parsed.environment == "live"
    assert parsed.scopes == SECTION_15_REQUEST["scopes"]
    assert parsed.model_dump(mode="json") == SECTION_15_REQUEST


def test_created_response_accepts_section_15_payload_verbatim() -> None:
    parsed = ApiKeyCreatedResponse.model_validate(SECTION_15_RESPONSE)
    assert list(ApiKeyCreatedResponse.model_fields) == ["id", "name", "key", "created_at"]
    assert parsed.model_dump(mode="json") == SECTION_15_RESPONSE


@pytest.mark.parametrize("environment", ["production", "LIVE", "sandbox", "", None])
def test_create_request_rejects_invalid_environment(environment: object) -> None:
    payload = {**SECTION_15_REQUEST, "environment": environment}
    with pytest.raises(ValidationError):
        ApiKeyCreateRequest.model_validate(payload)


@pytest.mark.parametrize(
    "scope",
    [
        "vispector:inspection",  # two segments
        "vispector:inspection:run:extra",  # four segments
        "VISPECTOR:inspection:run",  # uppercase
        "vispector::run",  # empty segment
        "1vispector:inspection:run",  # segment must start lowercase a-z
        "",
    ],
)
def test_create_request_rejects_invalid_scopes(scope: str) -> None:
    payload = {**SECTION_15_REQUEST, "scopes": [scope]}
    with pytest.raises(ValidationError):
        ApiKeyCreateRequest.model_validate(payload)


@pytest.mark.parametrize(
    "extra",
    [{"secret": "fn_live_x_y"}, {"secret_hash": "abc"}, {"key": "fn_live_x_y"}],
)
def test_create_request_forbids_secret_bearing_and_unknown_fields(extra: dict) -> None:
    with pytest.raises(ValidationError):
        ApiKeyCreateRequest.model_validate({**SECTION_15_REQUEST, **extra})


def test_create_request_requires_scopes_field_but_allows_empty_list() -> None:
    omitted = {k: v for k, v in SECTION_15_REQUEST.items() if k != "scopes"}
    with pytest.raises(ValidationError):
        ApiKeyCreateRequest.model_validate(omitted)
    assert ApiKeyCreateRequest.model_validate({**SECTION_15_REQUEST, "scopes": []}).scopes == []


def test_created_response_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ApiKeyCreatedResponse.model_validate({**SECTION_15_RESPONSE, "secret_hash": "abc"})


# --- masked key summary ---------------------------------------------------------


def test_summary_field_list_is_masked_only() -> None:
    assert list(ApiKeySummary.model_fields) == [
        "id",
        "name",
        "environment",
        "key_prefix",
        "status",
        "scopes",
        "created_at",
        "last_used_at",
        "expires_at",
        "revoked_at",
    ]


@pytest.mark.parametrize(
    "extra",
    [
        {"secret_hash": "6f7c8b9d"},
        {"secret": "fn_live_01JXYZ7K_a8f3"},
        {"key": "fn_live_01JXYZ7K_a8f3"},
        {"key_id": "01JXYZ7K"},  # §8 credential segment stays internal
    ],
)
def test_summary_rejects_secret_and_segment_fields(extra: dict) -> None:
    with pytest.raises(ValidationError):
        ApiKeySummary.model_validate({**VALID_SUMMARY, **extra})


def test_summary_round_trips_and_serializes_utc() -> None:
    summary = ApiKeySummary.model_validate(VALID_SUMMARY)
    dumped = summary.model_dump(mode="json")
    assert dumped["created_at"] == CREATED_AT
    assert ApiKeySummary.model_validate(dumped) == summary


def test_page_of_summaries_serializes_with_opaque_cursor() -> None:
    page_model = Page[ApiKeySummary]
    page = page_model(
        items=[ApiKeySummary.model_validate(VALID_SUMMARY)],
        limit=20,
        next_cursor="eyJvZmZzZXQiOjIwfQ",  # adapter-defined; treated as opaque
    )
    dumped = page.model_dump(mode="json")
    assert set(dumped) == {"items", "limit", "next_cursor"}
    assert dumped["items"][0]["key_prefix"] == VALID_SUMMARY["key_prefix"]


# --- me / organizations / members -----------------------------------------------


def test_me_response_mirrors_user_fields_and_forbids_extras() -> None:
    assert list(MeResponse.model_fields) == list(User.model_fields)
    payload = {
        "id": "usr_01JXYZ7K",
        "display_name": "Ada",
        "email": "ada@example.com",
        "status": "active",
        "created_at": CREATED_AT,
        "updated_at": CREATED_AT,
    }
    MeResponse.model_validate(payload)
    with pytest.raises(ValidationError):
        MeResponse.model_validate({**payload, "external_identities": []})


def test_organization_create_requires_name_and_slug_with_derived_type_default() -> None:
    parsed = OrganizationCreateRequest.model_validate({"name": "Acme", "slug": "acme"})
    assert parsed.type == "customer"
    for payload in (
        {"slug": "acme"},
        {"name": "Acme"},
        {"name": "Acme", "slug": "acme", "status": "active"},
        {"name": "Acme", "slug": "acme", "id": "org_01JXYZ7K"},
    ):
        with pytest.raises(ValidationError):
            OrganizationCreateRequest.model_validate(payload)


def test_organization_response_shape_and_unknown_field_rejection() -> None:
    assert list(OrganizationResponse.model_fields) == [
        "id",
        "name",
        "slug",
        "type",
        "status",
        "created_at",
        "updated_at",
    ]
    payload = {
        "id": "org_01JXYZ7K",
        "name": "Acme",
        "slug": "acme",
        "type": "customer",
        "status": "active",
        "created_at": CREATED_AT,
        "updated_at": CREATED_AT,
    }
    OrganizationResponse.model_validate(payload)
    with pytest.raises(ValidationError):
        OrganizationResponse.model_validate({**payload, "secret": "x"})


def test_member_create_accepts_application_id_and_role_only() -> None:
    parsed = MemberCreateRequest.model_validate({"user_id": "usr_01JXYZ7K", "role": "admin"})
    assert str(parsed.user_id) == "usr_01JXYZ7K"
    invalid_payloads: list[dict[str, Any]] = [
        {"user_id": "mem_01JXYZ7K", "role": "admin"},  # record ID is not a user identity
        {"user_id": "6ad3b1f2-4c5d-4e6f-8a9b-0c1d2e3f4a5b", "role": "admin"},  # provider sub
        {"user_id": "usr_01JXYZ7K", "role": "superadmin"},
        {"user_id": "usr_01JXYZ7K", "role": "admin", "status": "disabled"},
        {"user_id": "usr_01JXYZ7K"},
    ]
    for payload in invalid_payloads:
        with pytest.raises(ValidationError):
            MemberCreateRequest.model_validate(payload)


def test_member_response_never_exposes_membership_record_id() -> None:
    assert list(MemberResponse.model_fields) == ["user_id", "role", "status", "created_at"]
    payload = {
        "user_id": "usr_01JXYZ7K",
        "role": "viewer",
        "status": "active",
        "created_at": CREATED_AT,
    }
    MemberResponse.model_validate(payload)
    with pytest.raises(ValidationError):
        MemberResponse.model_validate({**payload, "id": "mem_01JXYZ7K"})


def test_list_pages_validate_and_clamp_limit() -> None:
    org_page = Page[OrganizationResponse].model_validate(
        {
            "items": [
                {
                    "id": "org_01JXYZ7K",
                    "name": "Acme",
                    "slug": "acme",
                    "type": "personal",
                    "status": "active",
                    "created_at": CREATED_AT,
                    "updated_at": CREATED_AT,
                }
            ],
            "limit": 20,
            "next_cursor": None,
        }
    )
    assert org_page.items[0].slug == "acme"
    assert PageParams.model_validate({"limit": "500"}).limit == 100  # clamped, not rejected
    assert PageParams.model_validate({}).limit == 20
