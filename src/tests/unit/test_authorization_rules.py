"""Unit tests for the Phase 04 task-2 authorization rules and audit builders.

Covers the task's verify lines against stub storage (zero-write proofs) and
pure-function assertions:

1. The decision-4 classification matrix over (absent/disabled/active
   membership) x (active/disabled org) x (four roles) x (viewer/admin
   minimums), **including the precedence cells** (e.g. disabled org + absent
   membership => ``inactive_organization``).
2. The denial audit shape: metadata exactly ``{"reason", "operation"}`` with
   actor ``usr_``/org FK fields and no email/sub/token substrings in any
   field; ``audit_denial`` appends through ``append_audit_event`` and
   propagates failures (fail-closed).
3. All four builders deterministic under injected ``now``/ids.
4. The decision-3 guards raise the pinned errors with fixed, identifier-free
   messages.
5. Module purity: no FastAPI import (AST proof, suite-harness precedent).
"""

from __future__ import annotations

import ast
import dataclasses
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app.models.audit_event import AuditEvent
from app.models.enums import MembershipRole, MembershipStatus, OrganizationStatus, OrganizationType
from app.models.ids import AuditEventId, MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.services import authorization as rules
from app.services.authorization import (
    DENIAL_REASONS,
    ROLE_RANK,
    AccessDecision,
    AccessOutcome,
    MemberNotFoundError,
    MembershipConflictError,
    OrganizationSlugConflictError,
    OrganizationTypeNotSelectableError,
    OwnerMembershipImmutableError,
    OwnerRoleNotAssignableError,
    TargetUserNotFoundError,
    audit_denial,
    build_denial_audit,
    build_membership_created_audit,
    build_membership_removed_audit,
    build_organization_created_audit,
    classify_access,
    require_assignable_member_role,
    require_selectable_organization_type,
)
from app.storage.contract import StorageError

_NOW = datetime(2026, 9, 13, 9, 0, 0, 123456, tzinfo=UTC)
_ORG_ID = OrganizationId("org_rules_0001")
_ACTOR = UserId("usr_actor_0001")
_AUDIT_ID = AuditEventId("aud_rules_0001")
_MEMBERSHIP_ID = MembershipId("mem_rules_0001")

#: Provider material that must never appear in any audited field.
_SENTINEL_SUB = "11111111-2222-3333-4444-555555555555"
_SENTINEL_EMAIL = "victim@example.test"


class RecordingStorage:
    """Minimal stub recording every ``append_audit_event`` call."""

    def __init__(self, fail_with: Exception | None = None) -> None:
        self.appended: list[AuditEvent] = []
        self._fail_with = fail_with

    def append_audit_event(self, audit_event: AuditEvent) -> None:
        if self._fail_with is not None:
            raise self._fail_with
        self.appended.append(audit_event)


def _org(status: OrganizationStatus = OrganizationStatus.ACTIVE) -> Organization:
    return Organization(
        id=_ORG_ID,
        name="Rules Org",
        slug="rules-org",
        type=OrganizationType.CUSTOMER,
        status=status,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _membership(
    role: MembershipRole,
    status: MembershipStatus = MembershipStatus.ACTIVE,
) -> Membership:
    return Membership(
        id=_MEMBERSHIP_ID,
        organization_id=_ORG_ID,
        user_id=_ACTOR,
        role=role,
        status=status,
        created_at=_NOW,
    )


# ---------------------------------------------------------------------------
# 1. Role policy + classification matrix with pinned precedence
# ---------------------------------------------------------------------------


def test_role_rank_orders_viewer_below_member_below_admin_below_owner() -> None:
    assert set(ROLE_RANK) == set(MembershipRole)
    assert (
        ROLE_RANK[MembershipRole.VIEWER]
        < ROLE_RANK[MembershipRole.MEMBER]
        < ROLE_RANK[MembershipRole.ADMIN]
        < ROLE_RANK[MembershipRole.OWNER]
    )


def _expected(
    org_status: OrganizationStatus,
    membership: Membership | None,
    min_role: MembershipRole,
) -> AccessOutcome:
    """The decision-4 precedence, written independently of the implementation:
    org status, then presence, then membership status, then role rank."""
    if org_status is not OrganizationStatus.ACTIVE:
        return AccessOutcome.INACTIVE_ORGANIZATION
    if membership is None:
        return AccessOutcome.NO_MEMBERSHIP
    if membership.status is not MembershipStatus.ACTIVE:
        return AccessOutcome.INACTIVE_MEMBERSHIP
    if ROLE_RANK[membership.role] < ROLE_RANK[min_role]:
        return AccessOutcome.INSUFFICIENT_ROLE
    return AccessOutcome.GRANTED


_MEMBERSHIP_CASES: list[tuple[str, Membership | None]] = [
    ("absent", None),
    *[
        (f"active-{role.value}", _membership(role))
        for role in (
            MembershipRole.OWNER,
            MembershipRole.ADMIN,
            MembershipRole.MEMBER,
            MembershipRole.VIEWER,
        )
    ],
    *[
        (f"disabled-{role.value}", _membership(role, MembershipStatus.DISABLED))
        for role in (
            MembershipRole.OWNER,
            MembershipRole.ADMIN,
            MembershipRole.MEMBER,
            MembershipRole.VIEWER,
        )
    ],
]


@pytest.mark.parametrize("org_status", list(OrganizationStatus))
@pytest.mark.parametrize(
    "membership",
    [case_membership for _, case_membership in _MEMBERSHIP_CASES],
    ids=[label for label, _ in _MEMBERSHIP_CASES],
)
@pytest.mark.parametrize("min_role", [MembershipRole.VIEWER, MembershipRole.ADMIN])
def test_classify_access_matches_the_pinned_precedence_matrix(
    org_status: OrganizationStatus,
    membership: Membership | None,
    min_role: MembershipRole,
) -> None:
    decision = classify_access(_org(org_status), membership, min_role)
    assert decision == AccessDecision(_expected(org_status, membership, min_role))
    assert decision.is_granted is (decision.outcome is AccessOutcome.GRANTED)


def test_precedence_disabled_org_wins_over_absent_membership() -> None:
    # The decision-4 cell the matrix must pin for audit forensics: several
    # conditions hold at once, the reason is the *first* check.
    decision = classify_access(_org(OrganizationStatus.DISABLED), None, MembershipRole.ADMIN)
    assert decision.outcome is AccessOutcome.INACTIVE_ORGANIZATION


def test_precedence_absent_membership_wins_over_role_rank() -> None:
    decision = classify_access(_org(), None, MembershipRole.ADMIN)
    assert decision.outcome is AccessOutcome.NO_MEMBERSHIP


def test_precedence_disabled_membership_wins_over_insufficient_role() -> None:
    decision = classify_access(
        _org(),
        _membership(MembershipRole.VIEWER, MembershipStatus.DISABLED),
        MembershipRole.ADMIN,
    )
    assert decision.outcome is AccessOutcome.INACTIVE_MEMBERSHIP


def test_access_decision_is_frozen() -> None:
    decision = AccessDecision(AccessOutcome.GRANTED)
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.outcome = AccessOutcome.NO_MEMBERSHIP  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 2. Denial audit: shape, vocabulary, append behavior
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("reason", sorted(DENIAL_REASONS, key=lambda item: item.value))
def test_denial_audit_shape_is_exactly_reason_and_operation(reason: AccessOutcome) -> None:
    event = build_denial_audit(
        audit_id=_AUDIT_ID,
        organization_id=_ORG_ID,
        actor_user_id=_ACTOR,
        reason=reason,
        operation="get_organization",
        now=_NOW,
    )
    assert event.action == "authorization.denied"
    assert event.id == _AUDIT_ID  # value-equal (the model re-validates ID types)
    assert event.organization_id == _ORG_ID  # audit->org FK target
    assert event.actor_type == "user"
    assert isinstance(event.actor_id, UserId)
    assert event.actor_id == _ACTOR
    assert event.target_type is None and event.target_id is None  # broad action
    assert event.created_at == _NOW
    assert set(event.metadata) == {"reason", "operation"}
    assert event.metadata == {"reason": reason.value, "operation": "get_organization"}


def test_denial_audit_serialization_carries_no_provider_or_secret_material() -> None:
    event = build_denial_audit(
        audit_id=_AUDIT_ID,
        organization_id=_ORG_ID,
        actor_user_id=_ACTOR,
        reason=AccessOutcome.INSUFFICIENT_ROLE,
        operation="list_members",
        now=_NOW,
    )
    serialized = json.dumps(event.model_dump(mode="json"))
    # No email, no provider sub, no token material anywhere in any field.
    assert "@" not in serialized
    assert _SENTINEL_EMAIL not in serialized
    assert _SENTINEL_SUB not in serialized
    assert "bearer" not in serialized.lower()
    assert "eyj" not in serialized.lower()  # JWT segment shape


def test_denial_audit_rejects_granted_as_reason() -> None:
    with pytest.raises(ValueError, match="not an auditable denial reason"):
        build_denial_audit(
            audit_id=_AUDIT_ID,
            organization_id=_ORG_ID,
            actor_user_id=_ACTOR,
            reason=AccessOutcome.GRANTED,
            operation="get_organization",
            now=_NOW,
        )


def test_audit_denial_appends_exactly_one_event_via_storage() -> None:
    storage = RecordingStorage()
    audit_denial(
        storage,  # type: ignore[arg-type]
        _ACTOR,
        _ORG_ID,
        AccessOutcome.NO_MEMBERSHIP,
        "create_member",
        now=_NOW,
    )
    assert len(storage.appended) == 1
    event = storage.appended[0]
    assert event.action == "authorization.denied"
    assert event.metadata == {"reason": "no_membership", "operation": "create_member"}
    assert event.created_at == _NOW
    assert str(event.id).startswith("aud_")  # minted by the service, not storage


def test_audit_denial_defaults_to_one_clock_read(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = datetime(2026, 9, 13, 9, 30, 0, tzinfo=UTC)
    reads: list[bool] = []

    def fake_utc_now() -> datetime:
        reads.append(True)
        return clock

    monkeypatch.setattr(rules, "utc_now", fake_utc_now)
    storage = RecordingStorage()
    audit_denial(
        storage,  # type: ignore[arg-type]
        _ACTOR,
        _ORG_ID,
        AccessOutcome.INACTIVE_MEMBERSHIP,
        "remove_member",
    )
    assert reads == [True]  # exactly one clock read
    assert storage.appended[0].created_at == clock


def test_audit_denial_propagates_append_failure_fail_closed() -> None:
    # Decision 4: a denial that cannot be audited surfaces (500 upstream),
    # it never degrades into a silent 403.
    storage = RecordingStorage(fail_with=StorageError("storage write failed"))
    with pytest.raises(StorageError):
        audit_denial(
            storage,  # type: ignore[arg-type]
            _ACTOR,
            _ORG_ID,
            AccessOutcome.INSUFFICIENT_ROLE,
            "list_members",
            now=_NOW,
        )
    assert storage.appended == []


# ---------------------------------------------------------------------------
# 3. Mutation audit builders (decision 7) — deterministic under injected ids/now
# ---------------------------------------------------------------------------


def test_organization_created_audit_shape() -> None:
    event = build_organization_created_audit(
        audit_id=_AUDIT_ID,
        organization_id=_ORG_ID,
        actor_user_id=_ACTOR,
        organization_type=OrganizationType.CUSTOMER,
        now=_NOW,
    )
    assert event.action == "organization.created"
    assert event.metadata == {"type": "customer"}
    assert event.target_type == "organization"
    assert event.target_id == str(_ORG_ID)
    assert event.actor_type == "user" and event.actor_id == _ACTOR


@pytest.mark.parametrize(
    ("builder", "action"),
    [
        (build_membership_created_audit, "membership.created"),
        (build_membership_removed_audit, "membership.removed"),
    ],
)
def test_membership_audit_shapes_carry_role_and_mem_target(builder: Any, action: str) -> None:
    event = builder(
        audit_id=_AUDIT_ID,
        organization_id=_ORG_ID,
        actor_user_id=_ACTOR,
        membership_id=_MEMBERSHIP_ID,
        role=MembershipRole.MEMBER,
        now=_NOW,
    )
    assert event.action == action
    assert event.metadata == {"role": "member"}  # granted role / role at removal
    assert event.target_type == "membership"
    assert event.target_id == str(_MEMBERSHIP_ID)  # plain string, no FK


def test_builders_are_pure_in_injected_now_and_ids() -> None:
    first = build_membership_created_audit(
        audit_id=_AUDIT_ID,
        organization_id=_ORG_ID,
        actor_user_id=_ACTOR,
        membership_id=_MEMBERSHIP_ID,
        role=MembershipRole.ADMIN,
        now=_NOW,
    )
    second = build_membership_created_audit(
        audit_id=_AUDIT_ID,
        organization_id=_ORG_ID,
        actor_user_id=_ACTOR,
        membership_id=_MEMBERSHIP_ID,
        role=MembershipRole.ADMIN,
        now=_NOW,
    )
    assert first == second  # deterministic
    assert first.created_at == _NOW and first.id == _AUDIT_ID
    later = build_membership_created_audit(
        audit_id=AuditEventId("aud_rules_0002"),
        organization_id=_ORG_ID,
        actor_user_id=_ACTOR,
        membership_id=_MEMBERSHIP_ID,
        role=MembershipRole.ADMIN,
        now=_NOW.replace(microsecond=654321),
    )
    assert later.created_at != first.created_at
    assert later.id != first.id


# ---------------------------------------------------------------------------
# 4. Decision-3 guards with fixed, identifier-free messages
# ---------------------------------------------------------------------------


def test_customer_type_is_selectable() -> None:
    require_selectable_organization_type(OrganizationType.CUSTOMER)  # must not raise


@pytest.mark.parametrize("blocked", [OrganizationType.PERSONAL, OrganizationType.INTERNAL])
def test_non_customer_types_are_refused(blocked: OrganizationType) -> None:
    with pytest.raises(OrganizationTypeNotSelectableError) as excinfo:
        require_selectable_organization_type(blocked)
    assert str(excinfo.value) == ("only customer organizations can be created through this API")


@pytest.mark.parametrize(
    "allowed",
    [MembershipRole.VIEWER, MembershipRole.MEMBER, MembershipRole.ADMIN],
)
def test_non_owner_roles_are_assignable(allowed: MembershipRole) -> None:
    require_assignable_member_role(allowed)  # must not raise


def test_owner_role_is_not_assignable() -> None:
    with pytest.raises(OwnerRoleNotAssignableError) as excinfo:
        require_assignable_member_role(MembershipRole.OWNER)
    assert str(excinfo.value) == "the owner role cannot be granted through the membership API"


@pytest.mark.parametrize(
    ("error_class", "message"),
    [
        (MemberNotFoundError, "user is not a member of this organization"),
        (TargetUserNotFoundError, "target user does not exist"),
        (OrganizationSlugConflictError, "organization slug is already taken"),
        (MembershipConflictError, "user is already a member of this organization"),
        (OwnerMembershipImmutableError, "owner membership cannot be removed"),
    ],
)
def test_domain_error_messages_are_fixed_and_identifier_free(
    error_class: type[Exception],
    message: str,
) -> None:
    error = error_class()
    assert str(error) == message
    assert _ORG_ID not in str(error) and _ACTOR not in str(error)
    assert "@" not in str(error)


# ---------------------------------------------------------------------------
# 5. Module purity: no web-framework dependency above the service layer
# ---------------------------------------------------------------------------


def test_module_imports_no_fastapi_or_starlette() -> None:
    source = Path(rules.__file__).read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module)
    for module in imported:
        assert not module.startswith(("fastapi", "starlette")), module


def test_denial_reason_vocabulary_is_the_four_non_granted_outcomes() -> None:
    assert frozenset(set(AccessOutcome) - {AccessOutcome.GRANTED}) == DENIAL_REASONS
    assert {reason.value for reason in DENIAL_REASONS} == {
        "no_membership",
        "inactive_membership",
        "inactive_organization",
        "insufficient_role",
    }


def test_classify_access_takes_the_pinned_positional_signature() -> None:
    # (organization, membership|None, min_role) — positional, pure.
    absent = classify_access(_org(), None, MembershipRole.VIEWER)
    assert absent.outcome is AccessOutcome.NO_MEMBERSHIP
    granted = classify_access(_org(), _membership(MembershipRole.VIEWER), MembershipRole.VIEWER)
    assert granted.is_granted
