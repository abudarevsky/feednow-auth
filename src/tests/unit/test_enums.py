"""Unit tests for pinned domain enums (Phase 01 task 3)."""

from __future__ import annotations

import json
from enum import StrEnum

import pytest
from pydantic import BaseModel, ValidationError

from app.models.enums import (
    ApiKeyEnvironment,
    ApiKeyStatus,
    IdentityProvider,
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)

# Exact sets pinned by the Phase 01 breakdown (Planner decisions). Spec §4
# names the concepts but does not enumerate them; these values are frozen for
# Phase 02 (stored as strings) and Phase 05 (branched on).
PINNED_ENUM_VALUES: dict[type[StrEnum], set[str]] = {
    UserStatus: {"active", "disabled"},
    OrganizationStatus: {"active", "disabled"},
    MembershipStatus: {"active", "disabled"},
    ApiKeyStatus: {"active", "revoked"},
    MembershipRole: {"owner", "admin", "member", "viewer"},
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
