"""Unit tests for the Phase 13 task-3 administration service against stub storage.

These tests prove the *decision rules* of ``app.services.administration``
without a database, using a recording :class:`~app.storage.contract.Storage`
stub (the ``test_identity_service.py`` shape). The acceptance-critical proofs
live here:

- **resolution refusals never write** — zero matches raise
  ``AdministratorNotFoundError`` and many matches raise
  ``AmbiguousAdministratorEmailError`` (message = count + ``usr_`` ids only,
  no provider material) with zero transition calls;
- **one atomic transition call** — grant/revoke each reach
  ``transition_application_role`` exactly once with the pinned
  ``expected_role``/``new_role`` direction and a fully formed audit event
  (exact action, target, self-actor, two-key secret-free metadata, earliest
  active organization anchor);
- **anchor refusal precedes the transition** — no active organization raises
  ``AdministratorAuditAnchorMissingError`` before any transition call, so
  nothing can mutate and no entropy is consumed;
- **outcome mapping** — ``NO_CHANGE`` is returned untouched and the service
  never re-appends the skipped audit (the adapter's skip is final);
  ``LastActiveAdministratorError`` propagates untranslated (same instance).

Real-SQLite behavior (row persistence, audit counts, full rollback) is owned
by ``test_administration_sqlite.py``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.models.audit_event import AuditEvent
from app.models.enums import ApplicationRole, OrganizationStatus, OrganizationType
from app.models.ids import AuditEventId, OrganizationId, UserId
from app.models.organization import Organization
from app.models.pagination import Page, PageParams
from app.models.user import User
from app.services.administration import (
    GRANT_ACTION,
    REVOKE_ACTION,
    AdministratorAuditAnchorMissingError,
    AdministratorNotFoundError,
    AmbiguousAdministratorEmailError,
    grant_administrator,
    resolve_unique_user,
    revoke_administrator,
)
from app.storage.contract import (
    EntityNotFoundError,
    LastActiveAdministratorError,
    RoleTransition,
    RoleTransitionOutcome,
)

_NOW = datetime(2026, 9, 25, 10, 0, 0, tzinfo=UTC)
_EMAIL = "admin@example.test"
#: Provider material planted in fixtures to prove it never reaches messages.
_PROVIDER_SUB = "cognito-sub-1a2b3c"


def _user(
    user_id: str = "usr_admin_candidate",
    *,
    email: str = _EMAIL,
    application_role: ApplicationRole = ApplicationRole.USER,
) -> User:
    return User(
        id=UserId(user_id),
        display_name="Candidate",
        email=email,
        status="active",
        application_role=application_role,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _organization(
    organization_id: str = "org_earliest",
    *,
    created_at: datetime = _NOW,
) -> Organization:
    return Organization(
        id=OrganizationId(organization_id),
        name="Earliest Org",
        slug=f"org-{organization_id}",
        type=OrganizationType.CUSTOMER,
        status=OrganizationStatus.ACTIVE,
        created_at=created_at,
        updated_at=created_at,
    )


class StubStorage:
    """Recording ``Storage`` stub implementing only what task 3 touches.

    ``transition_application_role`` models the adapter contract: it records
    the full call, persists the audit **only** on the scripted
    ``TRANSITIONED`` outcome, and can raise a scripted error.
    ``append_audit_event`` exists solely to prove the service never re-appends
    a skipped audit; any call fails the test that asserts the audit count.
    """

    def __init__(self) -> None:
        self.users: list[User] = []
        self.organizations: list[Organization] = []
        self.email_reads: list[str] = []
        self.anchor_calls: list[tuple[str, int]] = []
        self.transition_calls: list[dict[str, object]] = []
        self.appended_audits: list[AuditEvent] = []
        self.persisted_audits: list[AuditEvent] = []
        # Scripted transition behavior (defaults: one clean TRANSITIONED).
        self.transition_outcome = RoleTransitionOutcome.TRANSITIONED
        self.transition_error: Exception | None = None

    # -- reads ---------------------------------------------------------------

    def list_users_by_email(self, email: str) -> list[User]:
        self.email_reads.append(email)
        return [user for user in self.users if user.email == email]

    def list_user_organizations(self, user_id: UserId, page: PageParams) -> Page[Organization]:
        self.anchor_calls.append((str(user_id), page.limit))
        return Page(items=self.organizations[: page.limit], limit=page.limit, next_cursor=None)

    # -- writes --------------------------------------------------------------

    def transition_application_role(
        self,
        *,
        user_id: UserId,
        expected_role: ApplicationRole,
        new_role: ApplicationRole,
        updated_at: datetime,
        audit_event: AuditEvent,
    ) -> RoleTransition:
        self.transition_calls.append(
            {
                "user_id": user_id,
                "expected_role": expected_role,
                "new_role": new_role,
                "updated_at": updated_at,
                "audit_event": audit_event,
            }
        )
        if self.transition_error is not None:
            raise self.transition_error
        stored = next(user for user in self.users if user.id == user_id)
        if self.transition_outcome is RoleTransitionOutcome.NO_CHANGE:
            # Adapter contract: zero writes, the audit event is NOT persisted.
            return RoleTransition(user=stored, outcome=RoleTransitionOutcome.NO_CHANGE)
        updated = stored.model_copy(update={"application_role": new_role, "updated_at": updated_at})
        self.persisted_audits.append(audit_event)
        return RoleTransition(user=updated, outcome=RoleTransitionOutcome.TRANSITIONED)

    def append_audit_event(self, audit_event: AuditEvent) -> None:
        self.appended_audits.append(audit_event)
        raise AssertionError("administration service must never append a standalone audit")

    # -- helpers -------------------------------------------------------------

    @property
    def write_calls(self) -> int:
        """Every mutation surface the service can reach."""
        return len(self.transition_calls) + len(self.appended_audits)


class CountingIds:
    """Deterministic ``aud_`` mint seam recording how often it was called."""

    def __init__(self, prefix: str = "aud_grant_") -> None:
        self._prefix = prefix
        self.calls = 0

    def __call__(self) -> AuditEventId:
        self.calls += 1
        return AuditEventId(f"{self._prefix}{self.calls:032d}")


class CountingNow:
    """Deterministic clock seam recording how often the service reads time."""

    def __init__(self, value: datetime = _NOW) -> None:
        self._value = value
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return self._value


def _stub_with_user(*users: User, organizations: list[Organization] | None = None) -> StubStorage:
    storage = StubStorage()
    storage.users.extend(users)
    storage.organizations.extend(organizations if organizations is not None else [_organization()])
    return storage


def _grant(
    storage: StubStorage,
    *,
    now: CountingNow | None = None,
    ids: CountingIds | None = None,
) -> RoleTransition:
    return grant_administrator(
        storage,  # type: ignore[arg-type]
        _EMAIL,
        now=now or CountingNow(),
        ids=ids or CountingIds(),
    )


# ---------------------------------------------------------------------------
# resolve_unique_user — the 0/1/many rule, read-only
# ---------------------------------------------------------------------------


def test_resolve_returns_the_single_exact_match_without_writing() -> None:
    user = _user()
    other = _user("usr_other", email="someone-else@example.test")
    storage = _stub_with_user(user, other)

    resolved = resolve_unique_user(storage, _EMAIL)  # type: ignore[arg-type]

    assert resolved == user
    # Exact-match lookup, called once with the address verbatim; zero writes.
    assert storage.email_reads == [_EMAIL]
    assert storage.write_calls == 0


def test_resolve_zero_matches_raises_not_found_without_writing() -> None:
    storage = _stub_with_user(_user(email="other@example.test"))

    with pytest.raises(AdministratorNotFoundError):
        resolve_unique_user(storage, _EMAIL)  # type: ignore[arg-type]

    assert storage.write_calls == 0
    assert storage.anchor_calls == []


def test_resolve_many_matches_raises_ambiguous_with_count_and_usr_ids() -> None:
    first = _user("usr_alpha0000000000000000000000000001")
    second = _user("usr_beta000000000000000000000000000002")
    storage = _stub_with_user(first, second)

    with pytest.raises(AmbiguousAdministratorEmailError) as excinfo:
        resolve_unique_user(storage, _EMAIL)  # type: ignore[arg-type]

    error = excinfo.value
    assert error.count == 2
    assert error.user_ids == (first.id, second.id)
    message = str(error)
    # Message carries the count and both usr_ ids...
    assert "2" in message
    assert str(first.id) in message
    assert str(second.id) in message
    # ...and nothing else: no provider material, not even the email.
    assert _EMAIL not in message
    assert _PROVIDER_SUB not in message
    assert "@" not in message
    assert storage.write_calls == 0


# ---------------------------------------------------------------------------
# grant_administrator — one transition call, one fully formed audit
# ---------------------------------------------------------------------------


def test_grant_calls_the_single_transition_with_the_pinned_audit_event() -> None:
    user = _user()
    organization = _organization()
    storage = _stub_with_user(user, organizations=[organization])
    now = CountingNow()
    ids = CountingIds()

    result = _grant(storage, now=now, ids=ids)

    assert result.outcome is RoleTransitionOutcome.TRANSITIONED
    assert result.user.application_role is ApplicationRole.ADMIN
    assert result.user.updated_at == _NOW
    assert len(storage.transition_calls) == 1
    call = storage.transition_calls[0]
    assert call["user_id"] == user.id
    assert call["expected_role"] is ApplicationRole.USER
    assert call["new_role"] is ApplicationRole.ADMIN
    assert call["updated_at"] == _NOW
    assert call["audit_event"] == AuditEvent(
        id=AuditEventId("aud_grant_" + "0" * 31 + "1"),
        organization_id=organization.id,
        actor_type="user",
        actor_id=user.id,
        action=GRANT_ACTION,
        target_type="user",
        target_id=str(user.id),
        metadata={"from_role": "user", "to_role": "admin"},
        created_at=_NOW,
    )
    # Exactly one clock read and one aud_ mint for the whole command.
    assert now.calls == 1
    assert ids.calls == 1


def test_grant_anchors_the_audit_on_the_earliest_active_organization() -> None:
    user = _user()
    earliest = _organization("org_earliest")
    storage = _stub_with_user(user, organizations=[earliest, _organization("org_later")])

    _grant(storage)

    # The same deterministic anchor /v1/me uses: limit-1 page, first item.
    assert storage.anchor_calls == [(str(user.id), 1)]
    audit = storage.transition_calls[0]["audit_event"]
    assert isinstance(audit, AuditEvent)
    assert audit.organization_id == earliest.id


def test_grant_without_active_organization_raises_before_any_transition() -> None:
    storage = _stub_with_user(_user(), organizations=[])
    now = CountingNow()
    ids = CountingIds()

    with pytest.raises(AdministratorAuditAnchorMissingError):
        _grant(storage, now=now, ids=ids)

    # Refusal mutates nothing and consumes no clock/entropy: the anchor read
    # is the last storage call made.
    assert storage.transition_calls == []
    assert storage.persisted_audits == []
    assert now.calls == 0
    assert ids.calls == 0


def test_grant_missing_user_raises_before_anchor_and_transition() -> None:
    storage = _stub_with_user(_user(email="other@example.test"))
    ids = CountingIds()

    with pytest.raises(AdministratorNotFoundError):
        _grant(storage, ids=ids)

    assert storage.anchor_calls == []
    assert storage.transition_calls == []
    assert storage.write_calls == 0
    assert ids.calls == 0


def test_grant_ambiguous_email_raises_with_ids_and_zero_mutation() -> None:
    first = _user("usr_ambiguous000000000000000000000001")
    second = _user("usr_ambiguous000000000000000000000002")
    storage = _stub_with_user(first, second)

    with pytest.raises(AmbiguousAdministratorEmailError) as excinfo:
        _grant(storage)

    assert [str(user_id) for user_id in excinfo.value.user_ids] == [str(first.id), str(second.id)]
    assert storage.write_calls == 0
    assert storage.anchor_calls == []


# ---------------------------------------------------------------------------
# revoke_administrator — flipped direction and action, same pipeline
# ---------------------------------------------------------------------------


def test_revoke_calls_the_single_transition_with_the_revoked_audit() -> None:
    user = _user(application_role=ApplicationRole.ADMIN)
    organization = _organization()
    storage = _stub_with_user(user, organizations=[organization])
    now = CountingNow()
    ids = CountingIds(prefix="aud_revoke_")

    result = revoke_administrator(
        storage,  # type: ignore[arg-type]
        _EMAIL,
        now=now,
        ids=ids,
    )

    assert result.outcome is RoleTransitionOutcome.TRANSITIONED
    assert result.user.application_role is ApplicationRole.USER
    assert len(storage.transition_calls) == 1
    call = storage.transition_calls[0]
    assert call["expected_role"] is ApplicationRole.ADMIN
    assert call["new_role"] is ApplicationRole.USER
    audit = call["audit_event"]
    assert isinstance(audit, AuditEvent)
    assert audit.action == REVOKE_ACTION
    assert audit.target_type == "user"
    assert audit.target_id == str(user.id)
    # Out-of-band self-actor: the affected user, per the pinned decision.
    assert audit.actor_type == "user"
    assert audit.actor_id == user.id
    assert audit.metadata == {"from_role": "admin", "to_role": "user"}
    assert now.calls == 1
    assert ids.calls == 1


# ---------------------------------------------------------------------------
# Outcome mapping — NO_CHANGE is asserted, never re-appended; guard errors
# propagate untranslated
# ---------------------------------------------------------------------------


def test_no_change_outcome_is_returned_without_any_second_audit() -> None:
    user = _user(application_role=ApplicationRole.ADMIN)
    storage = _stub_with_user(user)
    storage.transition_outcome = RoleTransitionOutcome.NO_CHANGE

    result = _grant(storage)

    # One transition call, adapter-reported NO_CHANGE echoed unchanged; the
    # skipped audit stays skipped (append_audit_event would fail the stub).
    assert result.outcome is RoleTransitionOutcome.NO_CHANGE
    assert result.user.application_role is ApplicationRole.ADMIN
    assert len(storage.transition_calls) == 1
    assert storage.persisted_audits == []
    assert storage.appended_audits == []


def test_last_active_administrator_error_propagates_untranslated() -> None:
    user = _user(application_role=ApplicationRole.ADMIN)
    storage = _stub_with_user(user)
    guard_error = LastActiveAdministratorError("refusing to demote the last active admin")
    storage.transition_error = guard_error

    with pytest.raises(LastActiveAdministratorError) as excinfo:
        revoke_administrator(storage, _EMAIL, now=CountingNow(), ids=CountingIds())  # type: ignore[arg-type]

    assert excinfo.value is guard_error
    assert storage.persisted_audits == []


def test_unexpected_storage_errors_propagate_untranslated() -> None:
    storage = _stub_with_user(_user())
    storage.transition_error = EntityNotFoundError("no user with id ...")

    with pytest.raises(EntityNotFoundError):
        _grant(storage)

    assert storage.appended_audits == []
