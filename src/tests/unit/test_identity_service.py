"""Unit tests for the Phase 03 task-4 identity service against stub storage.

These tests prove the *decision rules* of ``app.services.identity`` without a
database, using a recording :class:`~app.storage.contract.Storage` stub. The
two acceptance-critical proofs live here:

- **identity-hit makes exactly one identity read and zero writes** — a known
  user never re-provisions (the read-only context probes are asserted
  separately);
- **rejected/conflicting paths never mutate** — disabled users raise before
  any context read, and the email-collision race raises after exactly one
  (failed) ``provision_user`` attempt, never a second.

Per breakdown decision 7, the convergence test carries a *consistent*
``existing_user_id`` while the conflict test carries a **stranger's** id —
proving the service ignores that field for convergence and re-reads the
identity tuple instead. Real-SQLite behavior (row read-back, repeat-call
stability) is owned by ``test_identity_service_sqlite.py``.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

import pytest

from app.auth.cognito import CognitoClaims
from app.models.audit_event import AuditEvent
from app.models.authorization_context import AuthorizationContext
from app.models.enums import (
    IdentityProvider,
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.external_identity import ExternalIdentity, ProviderTenant
from app.models.ids import (
    AuditEventId,
    ExternalIdentityId,
    MembershipId,
    OrganizationId,
    ProviderSubject,
    UserId,
)
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.pagination import Page, PageParams
from app.models.user import User
from app.services.identity import (
    DisabledUserError,
    NoActiveOrganizationError,
    ProvisioningConflictError,
    ProvisioningIds,
    ResolvedIdentity,
    build_provisioning_batch,
    build_user_context,
    new_provisioning_ids,
    resolve_or_provision,
)
from app.storage.contract import (
    DuplicateExternalIdentityError,
    EntityNotFoundError,
    ProvisionedUser,
)

_NOW = datetime(2026, 9, 13, 8, 30, 0, tzinfo=UTC)
_ISSUER = "https://cognito.us-east-1.amazonaws.com/us-east-1_pool"


def _claims(
    *,
    sub: str = "cognito-sub-1",
    email: str = "dev@example.test",
    username: str | None = "Dev",
) -> CognitoClaims:
    return CognitoClaims(
        sub=sub,
        email=email,
        username=username,
        client_id="client-abc",
        iss=_ISSUER,
        exp=2000000000,
    )


def _identity_for(user: User, subject: str = "cognito-sub-1") -> ExternalIdentity:
    return ExternalIdentity(
        id=ExternalIdentityId("extid_existing"),
        user_id=user.id,
        provider=IdentityProvider.COGNITO,
        provider_subject=subject,
        provider_tenant=None,
        created_at=_NOW,
    )


def _user(
    user_id: str = "usr_existing",
    *,
    status: UserStatus = UserStatus.ACTIVE,
    email: str = "dev@example.test",
) -> User:
    return User(
        id=UserId(user_id),
        display_name="Existing",
        email=email,
        status=status,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _organization(
    organization_id: str = "org_existing",
    *,
    status: OrganizationStatus = OrganizationStatus.ACTIVE,
) -> Organization:
    return Organization(
        id=OrganizationId(organization_id),
        name="Existing Org",
        slug="existing-org",
        type=OrganizationType.CUSTOMER,
        status=status,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _membership(
    *,
    organization_id: str = "org_existing",
    user_id: str = "usr_existing",
    role: MembershipRole = MembershipRole.OWNER,
    status: MembershipStatus = MembershipStatus.ACTIVE,
) -> Membership:
    return Membership(
        id=MembershipId("mem_existing"),
        organization_id=OrganizationId(organization_id),
        user_id=UserId(user_id),
        role=role,
        status=status,
        created_at=_NOW,
    )


class StubStorage:
    """Recording ``Storage`` stub implementing only the methods task 4 touches.

    Call lists are append-only so tests can assert exact counts; identity
    lookups match the full ``(provider, provider_subject, provider_tenant)``
    tuple so a wrong-tuple read is a miss, not a hit.
    """

    def __init__(self) -> None:
        self.users: dict[str, User] = {}
        self.identities: dict[tuple[str, str, str | None], str] = {}
        self.organizations: dict[str, Organization] = {}
        self.memberships: dict[tuple[str, str], Membership] = {}
        self.identity_reads: list[tuple[str, str, str | None]] = []
        self.provision_calls: list[dict[str, object]] = []
        self.list_org_calls: list[tuple[str, int]] = []
        self.membership_reads: list[tuple[str, str]] = []
        self.organization_reads: list[str] = []
        # Optional scripted failure for provision_user (a race/conflict error).
        self.provision_error: DuplicateExternalIdentityError | None = None
        # Models the race window: the winner commits *after* our first read,
        # so the first identity lookup misses even though rows exist by the
        # time the convergence re-read runs.
        self.miss_first_identity_read = False

    # -- reads ---------------------------------------------------------------

    def get_user_by_external_identity(
        self,
        *,
        provider: IdentityProvider,
        provider_subject: ProviderSubject,
        provider_tenant: ProviderTenant | None = None,
    ) -> User:
        key = (str(provider), str(provider_subject), provider_tenant)
        self.identity_reads.append(key)
        if self.miss_first_identity_read and len(self.identity_reads) == 1:
            raise EntityNotFoundError("no such external identity (race window)")
        user_id = self.identities.get(key)
        if user_id is None:
            raise EntityNotFoundError("no such external identity")
        return self.users[user_id]

    def list_user_organizations(self, user_id: UserId, page: PageParams) -> Page[Organization]:
        self.list_org_calls.append((str(user_id), page.limit))
        orgs = sorted(
            (
                org
                for org in self.organizations.values()
                if self._is_active_member(str(user_id), org.id)
            ),
            key=lambda org: (org.created_at, str(org.id)),
        )
        return Page(items=orgs[: page.limit], limit=page.limit, next_cursor=None)

    def get_membership(self, *, organization_id: OrganizationId, user_id: UserId) -> Membership:
        key = (str(organization_id), str(user_id))
        self.membership_reads.append(key)
        membership = self.memberships.get(key)
        if membership is None:
            raise EntityNotFoundError("no such membership")
        return membership

    def get_organization(self, organization_id: OrganizationId) -> Organization:
        self.organization_reads.append(str(organization_id))
        organization = self.organizations.get(str(organization_id))
        if organization is None:
            raise EntityNotFoundError("no such organization")
        return organization

    # -- writes --------------------------------------------------------------

    def provision_user(
        self,
        *,
        user: User,
        identity: ExternalIdentity,
        organization: Organization,
        membership: Membership,
        audit_events: Sequence[AuditEvent],
    ) -> ProvisionedUser:
        self.provision_calls.append(
            {
                "user": user,
                "identity": identity,
                "organization": organization,
                "membership": membership,
                "audit_events": tuple(audit_events),
            }
        )
        if self.provision_error is not None:
            raise self.provision_error
        self._store(user, identity, organization, membership)
        return ProvisionedUser(
            user=user,
            identity=identity,
            organization=organization,
            membership=membership,
            audit_events=tuple(audit_events),
        )

    # -- helpers -------------------------------------------------------------

    def _store(
        self,
        user: User,
        identity: ExternalIdentity,
        organization: Organization,
        membership: Membership,
    ) -> None:
        self.users[str(user.id)] = user
        self.identities[
            (str(identity.provider), str(identity.provider_subject), identity.provider_tenant)
        ] = str(user.id)
        self.organizations[str(organization.id)] = organization
        self.memberships[(str(organization.id), str(user.id))] = membership

    def _is_active_member(self, user_id: str, organization_id: OrganizationId) -> bool:
        membership = self.memberships.get((str(organization_id), user_id))
        return membership is not None and membership.status is MembershipStatus.ACTIVE

    @property
    def write_calls(self) -> int:
        """Every mutation surface the service can reach (only ``provision_user``)."""
        return len(self.provision_calls)


def _seed_known_user(storage: StubStorage, user: User, organization: Organization) -> None:
    """Put ``user`` + ``organization`` + owner membership behind the standard sub."""
    storage._store(
        user,
        _identity_for(user),
        organization,
        _membership(organization_id=str(organization.id), user_id=str(user.id)),
    )


_IDS = ProvisioningIds(
    user_id=UserId("usr_" + "a" * 32),
    organization_id=OrganizationId("org_" + "b" * 32),
    external_identity_id=ExternalIdentityId("extid_" + "c" * 32),
    membership_id=MembershipId("mem_" + "d" * 32),
    user_created_audit_id=AuditEventId("aud_" + "e" * 32),
    organization_created_audit_id=AuditEventId("aud_" + "f" * 32),
    membership_created_audit_id=AuditEventId("aud_" + "0" * 32),
)


# ---------------------------------------------------------------------------
# build_provisioning_batch - pure, exact values (decisions 5-8)
# ---------------------------------------------------------------------------


def test_batch_entities_match_pinned_values() -> None:
    batch = build_provisioning_batch(_claims(), _NOW, _IDS)

    assert batch.user.id == _IDS.user_id
    assert batch.user.display_name == "Dev"
    assert batch.user.email == "dev@example.test"
    assert batch.user.status is UserStatus.ACTIVE
    assert batch.user.created_at == _NOW and batch.user.updated_at == _NOW

    assert batch.identity.id == _IDS.external_identity_id
    assert batch.identity.user_id == _IDS.user_id
    assert batch.identity.provider is IdentityProvider.COGNITO
    assert batch.identity.provider_subject == "cognito-sub-1"
    assert batch.identity.provider_tenant is None
    assert batch.identity.created_at == _NOW

    assert batch.organization.id == _IDS.organization_id
    assert batch.organization.name == "Dev's Workspace"
    assert batch.organization.slug == f"personal-{_IDS.user_id}"
    assert batch.organization.type is OrganizationType.PERSONAL
    assert batch.organization.status is OrganizationStatus.ACTIVE
    assert batch.organization.created_at == _NOW and batch.organization.updated_at == _NOW

    assert batch.membership.id == _IDS.membership_id
    assert batch.membership.organization_id == _IDS.organization_id
    assert batch.membership.user_id == _IDS.user_id
    assert batch.membership.role is MembershipRole.OWNER
    assert batch.membership.status is MembershipStatus.ACTIVE
    assert batch.membership.created_at == _NOW


def test_batch_display_name_falls_back_to_sub_and_never_email() -> None:
    claims = _claims(username=None, email="stranger@example.test")
    batch = build_provisioning_batch(claims, _NOW, _IDS)
    assert batch.user.display_name == "cognito-sub-1"
    assert batch.organization.name == "cognito-sub-1's Workspace"
    assert "stranger" not in batch.organization.slug


def test_batch_audits_exact_order_targets_and_metadata() -> None:
    events = build_provisioning_batch(_claims(), _NOW, _IDS).audit_events

    assert [event.action for event in events] == [
        "user.created",
        "organization.created",
        "membership.created",
    ]
    assert [(event.target_type, event.target_id) for event in events] == [
        ("user", str(_IDS.user_id)),
        ("organization", str(_IDS.organization_id)),
        ("membership", str(_IDS.membership_id)),
    ]
    assert [event.metadata for event in events] == [
        {"provider": "cognito"},
        {"type": "personal"},
        {"role": "owner"},
    ]
    for event in events:
        assert event.actor_type == "user"
        assert event.actor_id == _IDS.user_id  # self-provisioning actor
        assert event.organization_id == _IDS.organization_id
        assert event.created_at == _NOW
    assert [event.id for event in events] == [
        _IDS.user_created_audit_id,
        _IDS.organization_created_audit_id,
        _IDS.membership_created_audit_id,
    ]


def test_new_provisioning_ids_are_fresh_and_prefix_valid() -> None:
    first, second = new_provisioning_ids(), new_provisioning_ids()
    assert first.user_id != second.user_id
    assert str(first.user_id).startswith("usr_")
    assert str(first.organization_id).startswith("org_")
    assert str(first.external_identity_id).startswith("extid_")
    assert str(first.membership_id).startswith("mem_")
    audit_ids = {
        first.user_created_audit_id,
        first.organization_created_audit_id,
        first.membership_created_audit_id,
    }
    assert all(str(audit_id).startswith("aud_") for audit_id in audit_ids)
    assert len(audit_ids) == 3


# ---------------------------------------------------------------------------
# resolve_or_provision — hit path: one identity read, zero writes
# ---------------------------------------------------------------------------


def test_identity_hit_makes_one_identity_read_and_zero_writes() -> None:
    storage = StubStorage()
    existing = _user()
    _seed_known_user(storage, existing, _organization())

    resolved = resolve_or_provision(storage, _claims())

    assert isinstance(resolved, ResolvedIdentity)
    assert resolved.user is existing
    assert storage.identity_reads == [(str(IdentityProvider.COGNITO), "cognito-sub-1", None)]
    assert storage.write_calls == 0
    assert resolved.context == AuthorizationContext(
        actor_type="user",
        actor_id=existing.id,
        organization_id=OrganizationId("org_existing"),
        roles=[MembershipRole.OWNER],
        scopes=[],
    )


# ---------------------------------------------------------------------------
# resolve_or_provision — miss path: exactly one fully formed batch
# ---------------------------------------------------------------------------


def test_miss_provisions_exactly_once_with_fully_formed_batch() -> None:
    storage = StubStorage()

    resolved = resolve_or_provision(storage, _claims(), now=_NOW, ids=_IDS)

    assert len(storage.provision_calls) == 1
    expected = build_provisioning_batch(_claims(), _NOW, _IDS)
    call = storage.provision_calls[0]
    assert call["user"] == expected.user
    assert call["identity"] == expected.identity
    assert call["organization"] == expected.organization
    assert call["membership"] == expected.membership
    assert call["audit_events"] == expected.audit_events
    assert resolved.user == expected.user
    assert resolved.context.organization_id == _IDS.organization_id
    assert resolved.context.roles == [MembershipRole.OWNER]
    assert resolved.context.scopes == []


def test_miss_without_injected_ids_mints_prefix_valid_ids() -> None:
    storage = StubStorage()
    resolved = resolve_or_provision(storage, _claims(), now=_NOW)

    assert len(storage.provision_calls) == 1
    call = storage.provision_calls[0]
    created_user = call["user"]
    assert isinstance(created_user, User)
    assert str(created_user.id).startswith("usr_")
    assert str(call["organization"].slug) == f"personal-{created_user.id}"
    assert resolved.context.actor_type == "user"


def test_miss_lookup_uses_pinned_cognito_tuple() -> None:
    """The lookup pins ``(cognito, sub, None)`` — Shopify-shaped reads can never
    collide with the Cognito seam (decision 4)."""
    storage = StubStorage()
    resolve_or_provision(storage, _claims(), now=_NOW, ids=_IDS)
    assert storage.identity_reads == [(str(IdentityProvider.COGNITO), "cognito-sub-1", None)]


# ---------------------------------------------------------------------------
# Race convergence vs. email collision (decision 7)
# ---------------------------------------------------------------------------


def test_race_converges_on_re_read_with_no_second_provision() -> None:
    """Winner's rows exist; provision raised the race error with a *consistent*
    existing_user_id — convergence must come from the identity re-read."""
    storage = StubStorage()
    winner = _user("usr_winner")
    _seed_known_user(storage, winner, _organization("org_winner"))
    storage.miss_first_identity_read = True  # winner committed after our read
    storage.provision_error = DuplicateExternalIdentityError(existing_user_id=UserId("usr_winner"))

    resolved = resolve_or_provision(storage, _claims(), now=_NOW, ids=_IDS)

    assert len(storage.provision_calls) == 1  # the failed attempt; never a retry
    assert resolved.user is winner
    assert resolved.context.organization_id == OrganizationId("org_winner")
    assert len(storage.identity_reads) == 2  # lookup + convergence re-read


def test_race_convergence_ignores_existing_user_id_when_none() -> None:
    storage = StubStorage()
    winner = _user("usr_winner")
    _seed_known_user(storage, winner, _organization("org_winner"))
    storage.miss_first_identity_read = True
    storage.provision_error = DuplicateExternalIdentityError(existing_user_id=None)

    resolved = resolve_or_provision(storage, _claims(), now=_NOW, ids=_IDS)

    assert resolved.user is winner


def test_email_collision_raises_conflict_and_ignores_stranger_id() -> None:
    """Decision 7's trap: the adapter resolves ``existing_user_id`` via an
    email fallback, so in the not-a-race case it names a *stranger*. The
    identity re-read misses; the service must raise the conflict and never
    converge on (or return) the stranger's id."""
    storage = StubStorage()
    stranger = _user("usr_stranger", email="dev@example.test")
    storage.users["usr_stranger"] = stranger  # email taken, different identity
    storage.provision_error = DuplicateExternalIdentityError(
        existing_user_id=UserId("usr_stranger")
    )

    with pytest.raises(ProvisioningConflictError):
        resolve_or_provision(storage, _claims(), now=_NOW, ids=_IDS)

    assert len(storage.provision_calls) == 1  # no second attempt
    assert len(storage.identity_reads) == 2  # lookup + re-read (the only convergence signal)
    assert storage.write_calls == 1  # the single failed batch; nothing else mutated


def test_convergence_cross_check_refuses_inconsistent_winner() -> None:
    """Post-convergence cross-check: re-read found usr_winner but the adapter
    claims usr_other — storage told us two different users; refuse to pick."""
    storage = StubStorage()
    winner = _user("usr_winner")
    _seed_known_user(storage, winner, _organization("org_winner"))
    storage.miss_first_identity_read = True
    storage.provision_error = DuplicateExternalIdentityError(existing_user_id=UserId("usr_other"))

    with pytest.raises(ProvisioningConflictError):
        resolve_or_provision(storage, _claims(), now=_NOW, ids=_IDS)


# ---------------------------------------------------------------------------
# Status and context rules
# ---------------------------------------------------------------------------


def test_disabled_user_raises_with_zero_writes_and_no_context_reads() -> None:
    storage = StubStorage()
    disabled = _user(status=UserStatus.DISABLED)
    _seed_known_user(storage, disabled, _organization())

    with pytest.raises(DisabledUserError):
        resolve_or_provision(storage, _claims())

    assert storage.write_calls == 0
    assert storage.list_org_calls == []  # raise happens before context building


def test_no_active_organization_raises() -> None:
    storage = StubStorage()
    storage.users["usr_existing"] = _user()
    storage.identities[(str(IdentityProvider.COGNITO), "cognito-sub-1", None)] = "usr_existing"

    with pytest.raises(NoActiveOrganizationError):
        resolve_or_provision(storage, _claims())

    assert storage.list_org_calls == [("usr_existing", 1)]  # earliest-active page probe


# ---------------------------------------------------------------------------
# build_user_context — explicit organization_id branch (decision 9)
# ---------------------------------------------------------------------------


def test_explicit_org_active_membership_and_org_resolves_to_that_org() -> None:
    storage = StubStorage()
    storage.organizations["org_target"] = _organization("org_target")
    storage.memberships[("org_target", "usr_existing")] = _membership(organization_id="org_target")

    context = build_user_context(storage, _user(), organization_id=OrganizationId("org_target"))

    assert context.organization_id == OrganizationId("org_target")
    assert context.roles == [MembershipRole.OWNER]
    assert context.scopes == []
    assert context.actor_type == "user"
    assert context.actor_id == UserId("usr_existing")
    assert storage.list_org_calls == []  # explicit branch never paginates


@pytest.mark.parametrize(
    ("organization", "membership"),
    [
        pytest.param(None, "active", id="org-missing"),
        pytest.param("disabled", "active", id="org-disabled"),
        pytest.param("active", None, id="membership-missing"),
        pytest.param("active", "disabled", id="membership-disabled"),
    ],
)
def test_explicit_org_rejections_all_raise_no_active_organization(
    organization: str | None,
    membership: str | None,
) -> None:
    storage = StubStorage()
    if organization is not None:
        storage.organizations["org_target"] = _organization(
            "org_target",
            status=OrganizationStatus(organization),
        )
    if membership is not None:
        storage.memberships[("org_target", "usr_existing")] = _membership(
            organization_id="org_target",
            status=MembershipStatus(membership),
        )

    with pytest.raises(NoActiveOrganizationError):
        build_user_context(storage, _user(), organization_id=OrganizationId("org_target"))


def test_default_branch_picks_earliest_active_organization() -> None:
    storage = StubStorage()
    later = datetime(2026, 9, 14, tzinfo=UTC)
    storage.organizations = {
        "org_older": _organization("org_older"),
        "org_newer": Organization(
            id=OrganizationId("org_newer"),
            name="Newer Org",
            slug="newer-org",
            type=OrganizationType.CUSTOMER,
            status=OrganizationStatus.ACTIVE,
            created_at=later,
            updated_at=later,
        ),
    }
    storage.memberships = {
        ("org_older", "usr_existing"): _membership(
            organization_id="org_older", role=MembershipRole.VIEWER
        ),
        ("org_newer", "usr_existing"): _membership(
            organization_id="org_newer", role=MembershipRole.ADMIN
        ),
    }

    context = build_user_context(storage, _user())

    assert context.organization_id == OrganizationId("org_older")
    assert context.roles == [MembershipRole.VIEWER]
    assert storage.list_org_calls == [("usr_existing", 1)]
