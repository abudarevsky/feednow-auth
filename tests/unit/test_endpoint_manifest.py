"""Unit tests for the frozen endpoint manifest (Phase 01 task 5).

Covers the task-5 verify item "manifest covers every §14 endpoint with 204
on both deletes", plus the mount-contract invariants Phase 04/05 rely on:
versioned prefix, method/path uniqueness, model pairing, pagination usage,
and application-identity path parameters (record IDs never mount).
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from app.api.schemas import (
    API_V1_PREFIX,
    ENDPOINTS,
    ApiKeyCreatedResponse,
    ApiKeyCreateRequest,
    ApiKeySummary,
    MemberCreateRequest,
    MemberResponse,
    MeResponse,
    OrganizationCreateRequest,
    OrganizationResponse,
    Page,
    endpoint_for,
)
from app.api.schemas.manifest import EndpointSpec
from app.models.ids import ApiKeyId, ApplicationId, OrganizationId, RecordId, UserId
from app.models.pagination import PageParams

# --- §14 route table, transcribed from the spec -------------------------------

SPEC_14_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/v1/me"),
        ("GET", "/v1/organizations"),
        ("POST", "/v1/organizations"),
        ("GET", "/v1/organizations/{organization_id}"),
        ("GET", "/v1/organizations/{organization_id}/members"),
        ("POST", "/v1/organizations/{organization_id}/members"),
        ("DELETE", "/v1/organizations/{organization_id}/members/{user_id}"),
        ("GET", "/v1/organizations/{organization_id}/api-keys"),
        ("POST", "/v1/organizations/{organization_id}/api-keys"),
        ("DELETE", "/v1/organizations/{organization_id}/api-keys/{key_id}"),
    }
)


def _routes() -> set[tuple[str, str]]:
    return {(spec.method, spec.path) for spec in ENDPOINTS}


def test_manifest_covers_every_section_14_endpoint_exactly() -> None:
    assert _routes() == set(SPEC_14_ROUTES)
    assert len(ENDPOINTS) == len(SPEC_14_ROUTES)


def test_api_v1_prefix_constant_and_path_usage() -> None:
    assert API_V1_PREFIX == "/v1"
    for spec in ENDPOINTS:
        assert spec.path.startswith(f"{API_V1_PREFIX}/"), spec


def test_operation_ids_are_unique_and_lookup_works() -> None:
    ids = [spec.operation_id for spec in ENDPOINTS]
    assert len(ids) == len(set(ids))
    assert endpoint_for("revoke_api_key").method == "DELETE"
    with pytest.raises(KeyError):
        endpoint_for("rotate_api_key")  # rotation explicitly not in Phase 01


def test_both_deletes_are_204_with_no_request_or_response_body() -> None:
    deletes = [spec for spec in ENDPOINTS if spec.method == "DELETE"]
    assert {(spec.method, spec.path) for spec in deletes} == {
        ("DELETE", "/v1/organizations/{organization_id}/members/{user_id}"),
        ("DELETE", "/v1/organizations/{organization_id}/api-keys/{key_id}"),
    }
    for spec in deletes:
        assert spec.success_status == 204, spec
        assert spec.response_model is None, spec
        assert spec.request_model is None, spec


def test_gets_are_200_and_creates_are_201() -> None:
    for spec in ENDPOINTS:
        if spec.method == "GET":
            assert spec.success_status == 200, spec
            assert spec.request_model is None, spec
        elif spec.method == "POST":
            assert spec.success_status == 201, spec
            assert spec.request_model is not None, spec


def test_list_endpoints_declare_pagination_and_page_models() -> None:
    paginated = {(spec.method, spec.path) for spec in ENDPOINTS if spec.paginated}
    assert paginated == {
        ("GET", "/v1/organizations"),
        ("GET", "/v1/organizations/{organization_id}/members"),
        ("GET", "/v1/organizations/{organization_id}/api-keys"),
    }
    for spec in ENDPOINTS:
        if spec.paginated:
            assert spec.query_model is PageParams, spec
            assert issubclass(spec.response_model, Page), spec
        else:
            assert spec.query_model is None, spec


def test_page_parameterizations_match_resource_models() -> None:
    by_route = {(spec.method, spec.path): spec for spec in ENDPOINTS}
    assert by_route[("GET", "/v1/me")].response_model is MeResponse
    organizations = by_route[("GET", "/v1/organizations")]
    assert organizations.item_model is OrganizationResponse
    assert by_route[("POST", "/v1/organizations")].response_model is OrganizationResponse
    assert by_route[("POST", "/v1/organizations")].request_model is OrganizationCreateRequest
    assert by_route[("GET", "/v1/organizations/{organization_id}")].response_model is (
        OrganizationResponse
    )
    members = "/v1/organizations/{organization_id}/members"
    assert by_route[("GET", members)].item_model is MemberResponse
    assert by_route[("POST", members)].request_model is MemberCreateRequest
    assert by_route[("POST", members)].response_model is MemberResponse
    keys = "/v1/organizations/{organization_id}/api-keys"
    assert by_route[("GET", keys)].item_model is ApiKeySummary
    assert by_route[("POST", keys)].request_model is ApiKeyCreateRequest
    assert by_route[("POST", keys)].response_model is ApiKeyCreatedResponse


def test_path_params_are_application_identities_only() -> None:
    seen: list[tuple[str, type]] = []
    for spec in ENDPOINTS:
        for name, param_type in spec.path_params.items():
            assert issubclass(param_type, ApplicationId), (spec.operation_id, name)
            assert not issubclass(param_type, RecordId), (spec.operation_id, name)
            seen.append((name, param_type))
    assert ("organization_id", OrganizationId) in seen
    assert ("user_id", UserId) in seen
    # The §14 {key_id} path parameter is the key_ application identity,
    # NOT the §8 non-secret credential segment (Phase 05 internal).
    assert ("key_id", ApiKeyId) in seen


def test_creation_response_is_only_manifest_model_with_full_key() -> None:
    models: list[type[BaseModel]] = []
    for spec in ENDPOINTS:
        models.extend(m for m in (spec.request_model, spec.response_model) if m is not None)
        if spec.item_model is not None:
            models.append(spec.item_model)
    with_key = [model.__name__ for model in models if "key" in model.model_fields]
    assert with_key == ["ApiKeyCreatedResponse"]


# --- manifest self-validation (frozen contract guards) --------------------------


def test_endpoint_spec_rejects_contract_violations() -> None:
    with pytest.raises(ValueError, match="prefix"):
        EndpointSpec("x", "GET", "/v2/x", 200)
    with pytest.raises(ValueError, match="204"):
        EndpointSpec("x", "DELETE", f"{API_V1_PREFIX}/x", 204, response_model=MeResponse)
    with pytest.raises(ValueError, match="paginated"):
        EndpointSpec(
            "x", "GET", f"{API_V1_PREFIX}/x", 200, response_model=MeResponse, paginated=True
        )
    with pytest.raises(ValueError, match="query_model"):
        EndpointSpec(
            "x",
            "GET",
            f"{API_V1_PREFIX}/x",
            200,
            response_model=Page[MeResponse],
            paginated=True,
        )
    with pytest.raises(ValueError, match="request model"):
        EndpointSpec("x", "GET", f"{API_V1_PREFIX}/x", 200, request_model=MeResponse)
    with pytest.raises(ValueError, match="request model"):
        EndpointSpec("x", "POST", f"{API_V1_PREFIX}/x", 201)
    with pytest.raises(ValueError, match="placeholders"):
        EndpointSpec(
            "x",
            "GET",
            f"{API_V1_PREFIX}/x/{{organization_id}}",
            200,
            response_model=MeResponse,
            path_params={"user_id": UserId},
        )


def test_endpoints_tuple_is_immutable() -> None:
    assert isinstance(ENDPOINTS, tuple)
    with pytest.raises(TypeError):
        ENDPOINTS[0] = ENDPOINTS[1]  # type: ignore[index]
