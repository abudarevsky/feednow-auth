"""Unit tests for pinned domain enums (initial).

Current behavior and invariants: ``docs/architecture.md``."""

from __future__ import annotations

import json
from enum import StrEnum

import pytest
from pydantic import BaseModel, ValidationError

from app.models.enums import (
    ApiKeyEnvironment,
    ApiKeyStatus,
    ApplicationRole,
    IdentityProvider,
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)

# Exact sets pinned by the Phase 01 breakdown (Planner decisions). Spec §4
# names the concepts but does not enumerate them; these values are frozen for
# Phase 02 (stored as strings) and Phase 05 (branched on). Phase 12 adds
# ApplicationRole (spec 12 invariant 1).
PINNED_ENUM_VALUES: dict[type[StrEnum], set[str]] = {
    UserStatus: {"active", "disabled"},
    OrganizationStatus: {"active", "disabled"},
    MembershipStatus: {"active", "disabled"},
    ApiKeyStatus: {"active", "revoked"},
    MembershipRole: {"owner", "admin", "member", "viewer"},
    ApplicationRole: {"user", "admin"},
    OrganizationType: {"personal", "customer", "internal"},
    ApiKeyEnvironment: {"live", "test"},
    IdentityProvider: {"cognito", "shopify", "google", "microsoft", "oidc"},
}


@pytest.mark.parametrize("enum_type", list(PINNED_ENUM_VALUES))
def test_enum_values_exactly_pinned(enum_type):
    assert {member.value for member in enum_type} == PINNED_ENUM_VALUES[enum_type]


@pytest.mark.parametrize("enum_type", list(PINNED_ENUM_VALUES))
def test_enum_values_are_unique_no_aliases(enum_type):
    # Names carry no contract; values do. Sanity-check no accidental alias.
    assert len({member.value for member in enum_type}) == len(list(enum_type))


@pytest.mark.parametrize("enum_type", list(PINNED_ENUM_VALUES))
def test_known_value_validates_and_round_trips(enum_type):
    class Holder(BaseModel):
        value: enum_type

    for member in enum_type:
        model = Holder.model_validate_json(json.dumps({"value": member.value}))
        assert model.value is member
        assert json.loads(model.model_dump_json()) == {"value": member.value}


@pytest.mark.parametrize("enum_type", list(PINNED_ENUM_VALUES))
def test_unknown_enum_string_rejected(enum_type):
    class Holder(BaseModel):
        value: enum_type

    for bad in ("pending", "ACTIVE", "", "active ", "revoked"):
        if bad in {member.value for member in enum_type}:
            continue
        with pytest.raises(ValidationError):
            Holder(value=bad)


@pytest.mark.parametrize("enum_type", list(PINNED_ENUM_VALUES))
def test_non_string_input_rejected(enum_type):
    class Holder(BaseModel):
        value: enum_type

    with pytest.raises(ValidationError):
        Holder(value=1)


def test_api_key_status_has_no_expired_variant():
    # Expiry is derived from ``expires_at`` at verification time, never stored.
    assert "expired" not in {member.value for member in ApiKeyStatus}


def test_membership_status_has_no_removed_variant():
    # Member removal is a physical delete, not a status.
    assert "removed" not in {member.value for member in MembershipStatus}


def test_application_role_is_disjoint_from_membership_role():
    # Spec 12 invariant 1: the global application role is a separate enum from
    # the organization-local membership role — no shared code path, no
    # inheritance. The overlapping ``admin`` *string* is a naming coincidence
    # between two distinct vocabularies; the sets must not merge either way.
    assert ApplicationRole is not MembershipRole
    assert not issubclass(ApplicationRole, MembershipRole)
    assert not issubclass(MembershipRole, ApplicationRole)
    app_values = {member.value for member in ApplicationRole}
    org_values = {member.value for member in MembershipRole}
    # Organization-local roles never exist as application roles ...
    assert org_values - app_values == {"owner", "member", "viewer"}
    # ... and the global user role never exists as a membership role.
    assert "user" not in org_values


def test_application_role_default_value_is_user():
    # USER is the only role a writer obtains without naming it (the User
    # model default; proven end-to-end in test_identity_entities.py).
    assert ApplicationRole.USER == "user"
    assert ApplicationRole("user") is ApplicationRole.USER
