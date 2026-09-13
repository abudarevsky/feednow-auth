"""Adapter-neutral storage conformance suite (Phase 02, spec §11/§12).

This module holds the *behavior* cases every ``Storage`` adapter must pass.
It is imported unchanged by each adapter entry point (task 3:
``test_sqlite_contract.py``; Phase 06: a DynamoDB Local entry), so the rules
below are a reuse contract, not suggestions:

**Fixture contract every entry point must satisfy.** Each entry module
provides a pytest fixture named ``storage`` that yields an **initialized
adapter with all tables empty, per test**. The SQLite entry creates a fresh
temporary file through ``open_sqlite_storage``; the Phase 06 DynamoDB entry
must provide equivalent isolation (empty tables per test). Cases here never
depend on execution order or on data left behind by another case.

**Import isolation.** This module imports only ``app.storage.contract`` and
``app.models`` (plus pytest/stdlib): no adapter module, no driver, nothing
SQLite- or boto-specific. Coupling to a concrete adapter happens *only*
through the ``storage`` fixture supplied by the entry module;
``test_sqlite_contract.py`` asserts this by AST and by subprocess import.

**Deterministic builders.** The ``make_*`` helpers below construct domain
objects with literal prefix-valid IDs and fixed literal timestamps — no
generators and no ``utc_now()``. This is how the suite honors the contract
rule that storage mints nothing (entropy strategies are Phase 03/05 work)
while staying reproducible for Phase 06.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest

from app.models import (
    ApiKey,
    ApiKeyEnvironment,
    ApiKeyStatus,
    AuditEvent,
    ExternalIdentity,
    IdentityProvider,
    Membership,
    MembershipRole,
    MembershipStatus,
    Organization,
    OrganizationStatus,
    OrganizationType,
    User,
    UserStatus,
)
from app.models.ids import (
    ApiKeyId,
    AuditEventId,
    ExternalIdentityId,
    MembershipId,
    OrganizationId,
    UserId,
)
from app.models.pagination import MAX_PAGE_LIMIT, MIN_PAGE_LIMIT, Page, PageParams
from app.storage.contract import (
    DuplicateEntityError,
    DuplicateEntityKind,
    DuplicateExternalIdentityError,
    EntityNotFoundError,
    InvalidCursorError,
    ProvisionedOrganization,
    ProvisionedUser,
    ReferenceNotFoundError,
    Storage,
)

# ---------------------------------------------------------------------------
# Fixed literal timestamps (microsecond-bearing and zero-microsecond samples
# so later pagination cases can rely on the sortable encoding as well).
# ---------------------------------------------------------------------------

T0 = datetime(2026, 9, 12, 10, 0, 0, tzinfo=UTC)
T1 = datetime(2026, 9, 12, 10, 0, 0, 123456, tzinfo=UTC)
T2 = datetime(2026, 9, 12, 11, 0, 0, 654321, tzinfo=UTC)
# T3 shares T2's second but carries *zero* microseconds: a correct fixed-width
# encoding sorts it before T2, while an encoding that omits zero-microsecond
# fields would sort it after ("...00Z" > "...00.654321Z" lexicographically).
# Task 8's traversal cases use this pair as the sortable-encoding tripwire.
T3 = datetime(2026, 9, 12, 11, 0, 0, tzinfo=UTC)
T4 = datetime(2026, 9, 12, 12, 0, 0, 500000, tzinfo=UTC)

# ---------------------------------------------------------------------------
# Deterministic domain builders (see module docstring; used by tasks 3-8).
# ---------------------------------------------------------------------------


def make_user(
    *,
    user_id: str = "usr_test_0001",
    email: str | None = None,
    created_at: datetime = T0,
) -> User:
    """Build a fully formed ``User``; the default email derives from the id
    so distinct literal ids never collide on the email constraint by accident
    (tests that *want* an email conflict pass ``email`` explicitly)."""
    return User(
        id=UserId(user_id),
        display_name=f"Test user {user_id}",
        email=email or f"{user_id}@example.test",
        status=UserStatus.ACTIVE,
        created_at=created_at,
        updated_at=created_at,
    )


def make_identity(
    *,
    identity_id: str = "extid_test_0001",
    user_id: str = "usr_test_0001",
    provider: IdentityProvider = IdentityProvider.COGNITO,
    provider_subject: str = "subject-cognito-0001",
    provider_tenant: str | None = None,
    created_at: datetime = T0,
) -> ExternalIdentity:
    """Build a fully formed ``ExternalIdentity`` (tenant ``None`` by default,
    exercising the normalization rule on every adapter)."""
    return ExternalIdentity(
        id=ExternalIdentityId(identity_id),
        user_id=UserId(user_id),
        provider=provider,
        provider_subject=provider_subject,
        provider_tenant=provider_tenant,
        created_at=created_at,
    )


def make_organization(
    *,
    organization_id: str = "org_test_0001",
    slug: str | None = None,
    created_at: datetime = T0,
) -> Organization:
    """Build a fully formed ``Organization`` (default slug derives from the
    id so distinct ids stay slug-distinct unless a case overrides)."""
    return Organization(
        id=OrganizationId(organization_id),
        name=f"Test org {organization_id}",
        slug=slug or f"org-{organization_id}",
        type=OrganizationType.PERSONAL,
        status=OrganizationStatus.ACTIVE,
        created_at=created_at,
        updated_at=created_at,
    )


def make_membership(
    *,
    membership_id: str = "mem_test_0001",
    organization_id: str = "org_test_0001",
    user_id: str = "usr_test_0001",
    role: MembershipRole = MembershipRole.OWNER,
    status: MembershipStatus = MembershipStatus.ACTIVE,
    created_at: datetime = T0,
) -> Membership:
    """Build a fully formed ``Membership`` for one (organization, user) pair."""
    return Membership(
        id=MembershipId(membership_id),
        organization_id=OrganizationId(organization_id),
        user_id=UserId(user_id),
        role=role,
        status=status,
        created_at=created_at,
    )


def make_api_key(
    *,
    key_id: str = "key_test_0001",
    organization_id: str = "org_test_0001",
    created_by_user_id: str = "usr_test_0001",
    credential_segment: str = "01JTESTKEYID",
    scopes: list[str] | None = None,
    created_at: datetime = T1,
) -> ApiKey:
    """Build a fully formed ``ApiKey`` (``credential_segment`` is the §8
    non-secret segment, distinct from the ``key_`` application identity)."""
    return ApiKey(
        id=ApiKeyId(key_id),
        organization_id=OrganizationId(organization_id),
        created_by_user_id=UserId(created_by_user_id),
        name="conformance-key",
        key_id=credential_segment,
        key_prefix=f"fn_live_{credential_segment[:5]}",
        secret_hash="a" * 64,
        environment=ApiKeyEnvironment.LIVE,
        scopes=scopes if scopes is not None else ["vispector:inspection:read"],
        status=ApiKeyStatus.ACTIVE,
        created_at=created_at,
    )


def make_audit_event(
    *,
    audit_id: str = "aud_test_0001",
    organization_id: str = "org_test_0001",
    actor_user_id: str = "usr_test_0001",
    action: str = "user.provisioned",
    created_at: datetime = T0,
) -> AuditEvent:
    """Build a fully formed ``AuditEvent`` with JSON-safe metadata."""
    return AuditEvent(
        id=AuditEventId(audit_id),
        organization_id=OrganizationId(organization_id),
        actor_type="user",
        actor_id=UserId(actor_user_id),
        action=action,
        metadata={"conformance": True},
        created_at=created_at,
    )


# ---------------------------------------------------------------------------
# Task 3 — users: create/retrieve, not-found, duplicate email, duplicate id
# ---------------------------------------------------------------------------


def test_create_user_returns_and_persists_the_domain_user(storage: Storage) -> None:
    user = make_user()
    created = storage.create_user(user)
    # Caller-echo: the stored entity is returned unchanged (storage mints
    # nothing), and a read by id reconstructs the same domain object.
    assert created == user
    stored = storage.get_user(user.id)
    assert stored == user
    assert stored.status is UserStatus.ACTIVE


def test_get_unknown_user_raises_entity_not_found(storage: Storage) -> None:
    with pytest.raises(EntityNotFoundError):
        storage.get_user(UserId("usr_missing_0001"))


def test_duplicate_email_raises_user_email_conflict(storage: Storage) -> None:
    first = make_user()
    storage.create_user(first)
    # Email is a constraint, never an identity: a different usr_ id with a
    # taken email is rejected as a domain conflict.
    duplicate = make_user(user_id="usr_test_0002", email=first.email)
    with pytest.raises(DuplicateEntityError) as excinfo:
        storage.create_user(duplicate)
    assert excinfo.value.kind is DuplicateEntityKind.USER_EMAIL
    # The rejected write is fully rolled back: the original row is intact and
    # the rejected id was never consumed, so a clean insert of it succeeds.
    assert storage.get_user(first.id) == first
    storage.create_user(make_user(user_id="usr_test_0002"))


def test_duplicate_user_id_raises_entity_id_conflict(storage: Storage) -> None:
    first = make_user()
    storage.create_user(first)
    # A PRIMARY KEY collision is a domain conflict too (contract-pinned:
    # kind="entity_id", never a raw driver error).
    same_id = make_user(email="other@example.test")
    with pytest.raises(DuplicateEntityError) as excinfo:
        storage.create_user(same_id)
    assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID
    assert storage.get_user(first.id) == first


# ---------------------------------------------------------------------------
# Task 3 — external identities: create, tuple lookup (both tenant variants),
# not-found signal, duplicate rejection (proves '' normalization), FK
# ---------------------------------------------------------------------------


def test_identity_create_and_lookup_with_explicit_tenant(storage: Storage) -> None:
    user = make_user()
    storage.create_user(user)
    identity = make_identity(user_id=str(user.id), provider_tenant="shop-a.example.myshopify.com")
    created = storage.create_external_identity(identity)
    assert created == identity
    resolved = storage.get_user_by_external_identity(
        provider=identity.provider,
        provider_subject=identity.provider_subject,
        provider_tenant="shop-a.example.myshopify.com",
    )
    assert resolved == user
    # A different tenant is a different tuple: the lookup must not match.
    with pytest.raises(EntityNotFoundError):
        storage.get_user_by_external_identity(
            provider=identity.provider,
            provider_subject=identity.provider_subject,
            provider_tenant="shop-b.example.myshopify.com",
        )


def test_identity_create_and_lookup_with_none_tenant(storage: Storage) -> None:
    user = make_user()
    storage.create_user(user)
    identity = make_identity(user_id=str(user.id), provider_tenant=None)
    storage.create_external_identity(identity)
    # ``None`` resolves the same tuple whether passed explicitly or omitted
    # (the adapter normalizes None -> '' on both write and read).
    by_default = storage.get_user_by_external_identity(
        provider=identity.provider,
        provider_subject=identity.provider_subject,
    )
    by_none = storage.get_user_by_external_identity(
        provider=identity.provider,
        provider_subject=identity.provider_subject,
        provider_tenant=None,
    )
    assert by_default == user
    assert by_none == user


def test_unknown_identity_tuple_raises_entity_not_found(storage: Storage) -> None:
    # Pinned: a miss raises — never returns ``None``. This exception *is*
    # Phase 03's "needs provisioning" signal.
    with pytest.raises(EntityNotFoundError):
        storage.get_user_by_external_identity(
            provider=IdentityProvider.COGNITO,
            provider_subject="subject-never-seen",
        )


def test_duplicate_identity_with_explicit_tenant_is_rejected(storage: Storage) -> None:
    owner = make_user()
    other = make_user(user_id="usr_test_0002")
    storage.create_user(owner)
    storage.create_user(other)
    identity = make_identity(user_id=str(owner.id), provider_tenant="shop-a.example.myshopify.com")
    storage.create_external_identity(identity)
    # Same tuple under a different record id and a different user: the tuple
    # constraint, not the PK, must reject it.
    with pytest.raises(DuplicateEntityError) as excinfo:
        storage.create_external_identity(
            make_identity(
                identity_id="extid_test_0002",
                user_id=str(other.id),
                provider_tenant="shop-a.example.myshopify.com",
            )
        )
    assert excinfo.value.kind is DuplicateEntityKind.EXTERNAL_IDENTITY


def test_duplicate_identity_with_none_tenant_is_rejected(storage: Storage) -> None:
    # This case is what proves the '' normalization: with raw NULL tenants a
    # UNIQUE index would treat the rows as distinct and let a duplicate
    # cognito identity slip through.
    owner = make_user()
    other = make_user(user_id="usr_test_0002")
    storage.create_user(owner)
    storage.create_user(other)
    storage.create_external_identity(make_identity(user_id=str(owner.id)))
    with pytest.raises(DuplicateEntityError) as excinfo:
        storage.create_external_identity(
            make_identity(identity_id="extid_test_0002", user_id=str(other.id))
        )
    assert excinfo.value.kind is DuplicateEntityKind.EXTERNAL_IDENTITY


def test_identity_for_unknown_user_raises_reference_not_found(storage: Storage) -> None:
    with pytest.raises(ReferenceNotFoundError):
        storage.create_external_identity(make_identity(user_id="usr_ghost_0001"))


# ---------------------------------------------------------------------------
# Task 3 — boundary guarantees: domain types only, no identity coercion
# ---------------------------------------------------------------------------


def test_lookup_by_identity_returns_domain_user_without_row_leakage(
    storage: Storage,
) -> None:
    user = make_user()
    storage.create_user(user)
    identity = make_identity(user_id=str(user.id), provider_tenant="shop-a.example.myshopify.com")
    storage.create_external_identity(identity)
    resolved = storage.get_user_by_external_identity(
        provider=identity.provider,
        provider_subject=identity.provider_subject,
        provider_tenant="shop-a.example.myshopify.com",
    )
    # The exact domain ``User`` (equality already proves no extra columns:
    # the model is ``extra="forbid"``), never a row mapping or the identity.
    assert type(resolved) is User
    assert resolved == user
    assert not isinstance(resolved, dict)


def test_provider_subject_is_never_matched_as_a_user_id(storage: Storage) -> None:
    # A provider subject that *looks like* another user's id must still
    # resolve through the identity tuple to its owner — subjects are plain
    # provider strings and are never coerced into a UserId.
    owner = make_user()
    stranger = make_user(user_id="usr_test_0002")
    storage.create_user(owner)
    storage.create_user(stranger)
    identity = make_identity(user_id=str(owner.id), provider_subject="usr_test_0002")
    storage.create_external_identity(identity)
    resolved = storage.get_user_by_external_identity(
        provider=identity.provider,
        provider_subject="usr_test_0002",
    )
    assert resolved == owner
    assert resolved != stranger


# ---------------------------------------------------------------------------
# Task 4 — organizations: create/retrieve, not-found, duplicate slug/id
# ---------------------------------------------------------------------------


def test_create_organization_returns_and_persists_the_domain_organization(
    storage: Storage,
) -> None:
    organization = make_organization()
    created = storage.create_organization(organization)
    # Caller-echo: storage mints nothing; a read by id rebuilds the entity.
    assert created == organization
    stored = storage.get_organization(organization.id)
    assert stored == organization
    assert stored.status is OrganizationStatus.ACTIVE


def test_get_unknown_organization_raises_entity_not_found(storage: Storage) -> None:
    with pytest.raises(EntityNotFoundError):
        storage.get_organization(OrganizationId("org_missing_0001"))


def test_duplicate_slug_raises_organization_slug_conflict(storage: Storage) -> None:
    first = make_organization()
    storage.create_organization(first)
    # Slug is a constraint, never an identity: a different org_ id with a
    # taken slug is a domain conflict.
    duplicate = make_organization(organization_id="org_test_0002", slug=first.slug)
    with pytest.raises(DuplicateEntityError) as excinfo:
        storage.create_organization(duplicate)
    assert excinfo.value.kind is DuplicateEntityKind.ORGANIZATION_SLUG
    # Rejected write fully rolled back: original intact, rejected id not
    # consumed, so a clean (slug-distinct) insert of it succeeds.
    assert storage.get_organization(first.id) == first
    storage.create_organization(make_organization(organization_id="org_test_0002"))


def test_duplicate_organization_id_raises_entity_id_conflict(storage: Storage) -> None:
    first = make_organization()
    storage.create_organization(first)
    same_id = make_organization(slug="another-slug")
    with pytest.raises(DuplicateEntityError) as excinfo:
        storage.create_organization(same_id)
    assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID
    assert storage.get_organization(first.id) == first


# ---------------------------------------------------------------------------
# Task 4 — memberships: create + tuple lookup, duplicate pair, FK parents,
# active-membership filter, organization scoping, physical delete
# ---------------------------------------------------------------------------


def test_create_membership_and_get_by_domain_tuple(storage: Storage) -> None:
    user = make_user()
    organization = make_organization()
    storage.create_user(user)
    storage.create_organization(organization)
    membership = make_membership(organization_id=str(organization.id), user_id=str(user.id))
    created = storage.create_membership(membership)
    assert created == membership
    # Lookup is keyed by the (organization, user) tuple, never the mem_ id.
    stored = storage.get_membership(organization_id=organization.id, user_id=user.id)
    assert stored == membership
    assert stored.role is MembershipRole.OWNER


def test_duplicate_membership_pair_is_rejected(storage: Storage) -> None:
    user = make_user()
    organization = make_organization()
    storage.create_user(user)
    storage.create_organization(organization)
    storage.create_membership(make_membership())
    # Same (org, user) pair under a different mem_ id and role: the pair
    # constraint, not the PK, must reject it.
    with pytest.raises(DuplicateEntityError) as excinfo:
        storage.create_membership(
            make_membership(membership_id="mem_test_0002", role=MembershipRole.MEMBER)
        )
    assert excinfo.value.kind is DuplicateEntityKind.MEMBERSHIP


def test_get_unknown_membership_tuple_raises_entity_not_found(storage: Storage) -> None:
    user = make_user()
    organization = make_organization()
    storage.create_user(user)
    storage.create_organization(organization)
    # Both parents exist but no membership row: a miss raises, never None.
    with pytest.raises(EntityNotFoundError):
        storage.get_membership(organization_id=organization.id, user_id=user.id)
    with pytest.raises(EntityNotFoundError):
        storage.get_membership(
            organization_id=OrganizationId("org_ghost_0001"),
            user_id=UserId("usr_ghost_0001"),
        )


def test_membership_for_unknown_user_raises_reference_not_found(storage: Storage) -> None:
    organization = make_organization()
    storage.create_organization(organization)
    with pytest.raises(ReferenceNotFoundError):
        storage.create_membership(make_membership(user_id="usr_ghost_0001"))


def test_membership_for_unknown_organization_raises_reference_not_found(
    storage: Storage,
) -> None:
    user = make_user()
    storage.create_user(user)
    with pytest.raises(ReferenceNotFoundError):
        storage.create_membership(make_membership(organization_id="org_ghost_0001"))


def test_list_user_organizations_hides_disabled_memberships(storage: Storage) -> None:
    # A disabled membership is a suspension (pinned MembershipStatus
    # semantics): the organization disappears from the domain list even
    # though the membership row itself still resolves.
    user = make_user()
    active_org = make_organization(organization_id="org_test_0001")
    suspended_org = make_organization(organization_id="org_test_0002")
    storage.create_user(user)
    storage.create_organization(active_org)
    storage.create_organization(suspended_org)
    storage.create_membership(make_membership())
    storage.create_membership(
        make_membership(
            membership_id="mem_test_0002",
            organization_id="org_test_0002",
            user_id="usr_test_0001",
            status=MembershipStatus.DISABLED,
        )
    )
    page = storage.list_user_organizations(user.id, PageParams(limit=10))
    assert [organization.id for organization in page.items] == [active_org.id]
    assert page.next_cursor is None
    assert (
        storage.get_membership(organization_id=suspended_org.id, user_id=user.id).status
        is MembershipStatus.DISABLED
    )


def test_user_organization_lists_never_intersect(storage: Storage) -> None:
    user_a = make_user()
    user_b = make_user(user_id="usr_test_0002")
    org_a = make_organization(organization_id="org_test_0001")
    org_b = make_organization(organization_id="org_test_0002")
    storage.create_user(user_a)
    storage.create_user(user_b)
    storage.create_organization(org_a)
    storage.create_organization(org_b)
    storage.create_membership(make_membership(organization_id="org_test_0001"))
    storage.create_membership(
        make_membership(
            membership_id="mem_test_0002",
            organization_id="org_test_0002",
            user_id="usr_test_0002",
        )
    )
    ids_a = [
        organization.id
        for organization in storage.list_user_organizations(user_a.id, PageParams(limit=10)).items
    ]
    ids_b = [
        organization.id
        for organization in storage.list_user_organizations(user_b.id, PageParams(limit=10)).items
    ]
    assert ids_a == [org_a.id]
    assert ids_b == [org_b.id]
    assert not set(ids_a) & set(ids_b)


def test_list_memberships_is_organization_scoped(storage: Storage) -> None:
    # list_memberships shows ALL statuses (unlike the active-membership
    # filter of list_user_organizations) but only for the given organization.
    user_1 = make_user()
    user_2 = make_user(user_id="usr_test_0002")
    user_3 = make_user(user_id="usr_test_0003")
    org_1 = make_organization(organization_id="org_test_0001")
    org_2 = make_organization(organization_id="org_test_0002")
    for user in (user_1, user_2, user_3):
        storage.create_user(user)
    for organization in (org_1, org_2):
        storage.create_organization(organization)
    storage.create_membership(make_membership(organization_id="org_test_0001"))
    storage.create_membership(
        make_membership(
            membership_id="mem_test_0002",
            organization_id="org_test_0001",
            user_id="usr_test_0002",
            role=MembershipRole.MEMBER,
            status=MembershipStatus.DISABLED,
            created_at=T1,
        )
    )
    storage.create_membership(
        make_membership(
            membership_id="mem_test_0003",
            organization_id="org_test_0002",
            user_id="usr_test_0003",
        )
    )
    page = storage.list_memberships(org_1.id, PageParams(limit=10))
    assert [membership.user_id for membership in page.items] == [user_1.id, user_2.id]
    assert page.items[1].status is MembershipStatus.DISABLED
    other_page = storage.list_memberships(org_2.id, PageParams(limit=10))
    assert [membership.user_id for membership in other_page.items] == [user_3.id]


def test_delete_membership_is_physical_and_not_idempotent(storage: Storage) -> None:
    user = make_user()
    organization = make_organization()
    storage.create_user(user)
    storage.create_organization(organization)
    storage.create_membership(make_membership())
    storage.delete_membership(organization_id=organization.id, user_id=user.id)
    # Physical delete: the row is gone from both lookup paths.
    with pytest.raises(EntityNotFoundError):
        storage.get_membership(organization_id=organization.id, user_id=user.id)
    assert storage.list_user_organizations(user.id, PageParams(limit=10)).items == []
    # A second delete raises: removal is not idempotent (204-vs-404 is a
    # Phase 04 HTTP decision, not a storage one).
    with pytest.raises(EntityNotFoundError):
        storage.delete_membership(organization_id=organization.id, user_id=user.id)
    # The pair is free again for a fresh membership under a new mem_ id.
    storage.create_membership(make_membership(membership_id="mem_test_0002"))


# ---------------------------------------------------------------------------
# Task 4 — first multi-page use of keyset pagination in the list_* methods
# (task 8 hardens traversal determinism; these cases prove continuation
# works end-to-end for both organization-scoped lists).
# ---------------------------------------------------------------------------


def test_list_user_organizations_traverses_multiple_pages_in_order(storage: Storage) -> None:
    user = make_user()
    storage.create_user(user)
    org_early = make_organization(organization_id="org_test_0001", created_at=T0)
    org_late = make_organization(organization_id="org_test_0002", created_at=T1)
    org_last = make_organization(organization_id="org_test_0003", created_at=T2)
    for organization in (org_early, org_late, org_last):
        storage.create_organization(organization)
    storage.create_membership(make_membership(membership_id="mem_test_0001"))
    storage.create_membership(
        make_membership(
            membership_id="mem_test_0002",
            organization_id="org_test_0002",
            user_id="usr_test_0001",
        )
    )
    storage.create_membership(
        make_membership(
            membership_id="mem_test_0003",
            organization_id="org_test_0003",
            user_id="usr_test_0001",
        )
    )
    first = storage.list_user_organizations(user.id, PageParams(limit=2))
    assert [organization.id for organization in first.items] == [org_early.id, org_late.id]
    assert first.limit == 2
    assert first.next_cursor is not None
    second = storage.list_user_organizations(
        user.id,
        PageParams(limit=2, cursor=first.next_cursor),
    )
    assert [organization.id for organization in second.items] == [org_last.id]
    assert second.next_cursor is None


def test_list_memberships_traverses_multiple_pages_in_order(storage: Storage) -> None:
    organization = make_organization()
    storage.create_organization(organization)
    users = (
        make_user(user_id="usr_test_0001"),
        make_user(user_id="usr_test_0002"),
        make_user(user_id="usr_test_0003"),
    )
    for user in users:
        storage.create_user(user)
    storage.create_membership(make_membership(membership_id="mem_test_0001", created_at=T0))
    storage.create_membership(
        make_membership(
            membership_id="mem_test_0002",
            user_id="usr_test_0002",
            role=MembershipRole.MEMBER,
            created_at=T1,
        )
    )
    storage.create_membership(
        make_membership(
            membership_id="mem_test_0003",
            user_id="usr_test_0003",
            role=MembershipRole.VIEWER,
            created_at=T2,
        )
    )
    first = storage.list_memberships(organization.id, PageParams(limit=2))
    assert [membership.id for membership in first.items] == [
        MembershipId("mem_test_0001"),
        MembershipId("mem_test_0002"),
    ]
    assert first.next_cursor is not None
    second = storage.list_memberships(
        organization.id,
        PageParams(limit=2, cursor=first.next_cursor),
    )
    assert [membership.id for membership in second.items] == [MembershipId("mem_test_0003")]
    assert second.next_cursor is None


# ---------------------------------------------------------------------------
# Task 5 — API keys: create/retrieve by both identities, duplicate segment
# and record id, FK parents, org-scoped listing, the pinned key-read tenancy
# rule, exact scopes round-trip, and the revocation CAS (duplicate +
# concurrent first-write-wins, stored truth after revocation).
# ---------------------------------------------------------------------------


def _seed_key_owner(storage: Storage) -> tuple[User, Organization]:
    """Create the default builder user + organization for key cases."""
    user = make_user()
    organization = make_organization()
    storage.create_user(user)
    storage.create_organization(organization)
    return user, organization


def test_create_api_key_returns_and_persists_for_both_lookups(storage: Storage) -> None:
    _seed_key_owner(storage)
    api_key = make_api_key()
    created = storage.create_api_key(api_key)
    # Caller-echo: storage mints nothing.
    assert created == api_key
    # Retrieval by the key_ application identity...
    by_identity = storage.get_api_key(api_key.id)
    # ...and by the §8 credential segment (a different column and type).
    by_segment = storage.get_api_key_by_key_id(api_key.key_id)
    assert by_identity == api_key
    assert by_segment == api_key


def test_get_unknown_api_key_raises_entity_not_found(storage: Storage) -> None:
    # Both lookup paths raise on a miss — never return None.
    with pytest.raises(EntityNotFoundError):
        storage.get_api_key(ApiKeyId("key_missing_0001"))
    with pytest.raises(EntityNotFoundError):
        storage.get_api_key_by_key_id("01JNEVERISSUED")


def test_duplicate_credential_segment_raises_api_key_id_conflict(storage: Storage) -> None:
    _seed_key_owner(storage)
    first = make_api_key()
    storage.create_api_key(first)
    # Same §8 segment under a different key_ identity: the segment
    # constraint, not the PK, must reject it.
    with pytest.raises(DuplicateEntityError) as excinfo:
        storage.create_api_key(make_api_key(key_id="key_test_0002"))
    assert excinfo.value.kind is DuplicateEntityKind.API_KEY_ID
    # Rejected write fully rolled back: original intact, rejected key_ id
    # not consumed, so a clean (segment-distinct) insert of it succeeds.
    assert storage.get_api_key(first.id) == first
    storage.create_api_key(
        make_api_key(key_id="key_test_0002", credential_segment="01JOTHERSEGMENT")
    )


def test_duplicate_api_key_record_id_raises_entity_id_conflict(storage: Storage) -> None:
    _seed_key_owner(storage)
    first = make_api_key()
    storage.create_api_key(first)
    # A PRIMARY KEY collision on the key_ identity is a domain conflict too
    # (contract-pinned: kind="entity_id", never a raw driver error).
    same_id = make_api_key(credential_segment="01JOTHERSEGMENT")
    with pytest.raises(DuplicateEntityError) as excinfo:
        storage.create_api_key(same_id)
    assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID
    assert storage.get_api_key(first.id) == first


def test_api_key_for_unknown_organization_raises_reference_not_found(
    storage: Storage,
) -> None:
    user, _ = _seed_key_owner(storage)
    with pytest.raises(ReferenceNotFoundError):
        storage.create_api_key(
            make_api_key(organization_id="org_ghost_0001", created_by_user_id=str(user.id))
        )


def test_api_key_for_unknown_creator_raises_reference_not_found(storage: Storage) -> None:
    _, organization = _seed_key_owner(storage)
    with pytest.raises(ReferenceNotFoundError):
        storage.create_api_key(
            make_api_key(organization_id=str(organization.id), created_by_user_id="usr_ghost_0001")
        )


def test_api_key_scopes_round_trip_exactly(storage: Storage) -> None:
    _seed_key_owner(storage)
    # Order and duplicates are preserved verbatim: normalization is Phase 05
    # domain work, storage only round-trips.
    scopes = [
        "vispector:inspection:run",
        "vispector:inspection:read",
        "vispector:inspection:read",
        "feednow:billing:read",
    ]
    api_key = make_api_key(scopes=scopes)
    storage.create_api_key(api_key)
    assert storage.get_api_key(api_key.id).scopes == scopes
    assert storage.get_api_key_by_key_id(api_key.key_id).scopes == scopes


def test_list_api_keys_is_organization_scoped(storage: Storage) -> None:
    _seed_key_owner(storage)
    other_org = make_organization(organization_id="org_test_0002")
    storage.create_organization(other_org)
    storage.create_api_key(
        make_api_key(
            key_id="key_test_0001",
            organization_id="org_test_0001",
            credential_segment="01JSEGMENTAA",
            created_at=T1,
        )
    )
    storage.create_api_key(
        make_api_key(
            key_id="key_test_0002",
            organization_id="org_test_0001",
            credential_segment="01JSEGMENTAB",
            created_at=T2,
        )
    )
    storage.create_api_key(
        make_api_key(
            key_id="key_test_0003",
            organization_id="org_test_0002",
            credential_segment="01JSEGMENTBA",
            created_at=T0,
        )
    )
    page = storage.list_api_keys(OrganizationId("org_test_0001"), PageParams(limit=10))
    # (created_at, id) ascending, and no foreign-organization rows.
    assert [api_key.id for api_key in page.items] == [
        ApiKeyId("key_test_0001"),
        ApiKeyId("key_test_0002"),
    ]
    other_page = storage.list_api_keys(other_org.id, PageParams(limit=10))
    assert [api_key.id for api_key in other_page.items] == [ApiKeyId("key_test_0003")]


def test_get_api_key_is_not_org_filtered_by_contract(storage: Storage) -> None:
    # Pinned key-read tenancy rule: get_api_key takes only the key_ identity
    # and returns the full row regardless of organization — the §8
    # verification path must resolve the org *from* the key; enforcing the
    # §14 org-scoped route contract is the Phase 05 service's check of
    # organization_id, not a storage filter.
    _seed_key_owner(storage)
    foreign_org = make_organization(organization_id="org_test_0002")
    storage.create_organization(foreign_org)
    api_key = make_api_key(organization_id="org_test_0002")
    storage.create_api_key(api_key)
    stored = storage.get_api_key(api_key.id)
    assert stored == api_key
    assert stored.organization_id == foreign_org.id


def test_revoke_api_key_sets_status_and_revoked_at(storage: Storage) -> None:
    _seed_key_owner(storage)
    api_key = make_api_key()
    storage.create_api_key(api_key)
    revoked = storage.revoke_api_key(api_key.id, revoked_at=T2)
    assert revoked.status is ApiKeyStatus.REVOKED
    assert revoked.revoked_at == T2
    assert revoked.created_at == api_key.created_at
    assert revoked == storage.get_api_key(api_key.id)


def test_revoke_unknown_api_key_raises_entity_not_found(storage: Storage) -> None:
    # Only the active→revoked CAS is idempotent; absence is absence.
    with pytest.raises(EntityNotFoundError):
        storage.revoke_api_key(ApiKeyId("key_missing_0001"), revoked_at=T2)


def test_duplicate_revocation_preserves_the_first_revoked_at(storage: Storage) -> None:
    _seed_key_owner(storage)
    api_key = make_api_key()
    storage.create_api_key(api_key)
    first = storage.revoke_api_key(api_key.id, revoked_at=T1)
    # The second call carries a *distinct* literal revoked_at so
    # first-write-wins is observable, not coincidental: idempotent success
    # returning the stored key, no error.
    second = storage.revoke_api_key(api_key.id, revoked_at=T2)
    assert second == first
    assert second.revoked_at == T1
    assert storage.get_api_key(api_key.id).revoked_at == T1


def test_concurrent_revocations_preserve_the_first_revoked_at(storage: Storage) -> None:
    # Barrier + WAL, never sleeps (breakdown concurrency discipline). The
    # two racing calls carry distinct literal revoked_at values so the
    # winner is observable, not coincidental.
    _seed_key_owner(storage)
    api_key = make_api_key()
    storage.create_api_key(api_key)
    barrier = threading.Barrier(2)
    results: dict[str, ApiKey] = {}
    failures: dict[str, BaseException] = {}

    def revoke(token: str, revoked_at: datetime) -> None:
        try:
            barrier.wait()
            results[token] = storage.revoke_api_key(api_key.id, revoked_at=revoked_at)
        except Exception as exc:  # recorded; asserted empty on the main thread below
            failures[token] = exc

    threads = [
        threading.Thread(target=revoke, args=("early", T1)),
        threading.Thread(target=revoke, args=("late", T2)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == {}
    # Both racing calls succeed idempotently and report the same stored key;
    # exactly one of the two distinct literals won the CAS.
    assert results["early"] == results["late"]
    assert results["early"].status is ApiKeyStatus.REVOKED
    assert results["early"].revoked_at in (T1, T2)
    assert storage.get_api_key(api_key.id).revoked_at == results["early"].revoked_at


def test_revoked_key_still_resolves_by_segment_with_stored_truth(storage: Storage) -> None:
    # §13's "revoked key is rejected" maps to storage truthfulness: the
    # point lookup keeps resolving with status=revoked and revoked_at set —
    # the datum Phase 05 verification rejects on (status is data, not
    # deletion).
    _seed_key_owner(storage)
    api_key = make_api_key()
    storage.create_api_key(api_key)
    storage.revoke_api_key(api_key.id, revoked_at=T2)
    resolved = storage.get_api_key_by_key_id(api_key.key_id)
    assert resolved.status is ApiKeyStatus.REVOKED
    assert resolved.revoked_at == T2
    assert resolved.secret_hash == api_key.secret_hash
    # list_api_keys shows ALL statuses, including the revoked row.
    page = storage.list_api_keys(OrganizationId("org_test_0001"), PageParams(limit=10))
    assert [api_key.id for api_key in page.items] == [api_key.id]


# ---------------------------------------------------------------------------
# Task 6 — audit append: the standalone write path Phase 03-05 services use.
# Adapter-neutral only: the contract has NO audit read surface, so the
# duplicate-append proof below *is* how this suite observes persistence
# (mapper/codec checks live in the SQLite unit tests, never here).
# ---------------------------------------------------------------------------


def test_append_audit_event_returns_none(storage: Storage) -> None:
    organization = make_organization()
    storage.create_organization(organization)
    event = make_audit_event()
    # Contract-pinned: append returns ``None`` — storage mints nothing and
    # re-reads nothing, so there is nothing to return.
    assert storage.append_audit_event(event) is None


def test_duplicate_audit_append_raises_entity_id_conflict(storage: Storage) -> None:
    organization = make_organization()
    storage.create_organization(organization)
    storage.append_audit_event(make_audit_event())
    # Second append of the same aud_ id: with no read surface, this rejection
    # is the persistence proof — and a PRIMARY KEY collision is a domain
    # conflict (kind="entity_id", never a raw driver error).
    with pytest.raises(DuplicateEntityError) as excinfo:
        storage.append_audit_event(make_audit_event())
    assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID
    # The rejected append is fully rolled back: the connection stays usable
    # and a fresh event under a new aud_ id still appends.
    assert storage.append_audit_event(make_audit_event(audit_id="aud_test_0002")) is None


def test_audit_event_for_unknown_organization_raises_reference_not_found(
    storage: Storage,
) -> None:
    # audit→organization is the only parent an audit row references (the
    # actor id is §10 application identity enforced at the model boundary,
    # not a foreign key), so an unknown org must be rejected.
    with pytest.raises(ReferenceNotFoundError):
        storage.append_audit_event(make_audit_event(organization_id="org_ghost_0001"))


# ---------------------------------------------------------------------------
# Task 7 — provision_user atomic compound: happy path (every component via
# reads; audit persistence via task 6's duplicate-append proof), §6 race
# mapping (email/identity-tuple collision -> DuplicateExternalIdentityError
# carrying the winner's existing_user_id), email-duplicate/identity-absent
# fallback, membership-conflict full rollback, and the barrier race.
# ---------------------------------------------------------------------------


def test_provision_user_writes_every_component_atomically(storage: Storage) -> None:
    user = make_user()
    identity = make_identity(user_id="usr_test_0001")
    organization = make_organization()
    membership = make_membership()
    first_event = make_audit_event(audit_id="aud_test_0001")
    second_event = make_audit_event(
        audit_id="aud_test_0002", action="organization.created", created_at=T1
    )
    result = storage.provision_user(
        user=user,
        identity=identity,
        organization=organization,
        membership=membership,
        audit_events=[first_event, second_event],
    )
    # Caller-echo contract: the bundle carries the supplied objects unchanged
    # (storage mints nothing and does not re-read what it wrote).
    assert isinstance(result, ProvisionedUser)
    assert result.user == user
    assert result.identity == identity
    assert result.organization == organization
    assert result.membership == membership
    assert result.audit_events == (first_event, second_event)
    # Every component is observable through its contract read path...
    assert storage.get_user(user.id) == user
    assert (
        storage.get_user_by_external_identity(
            provider=identity.provider,
            provider_subject=identity.provider_subject,
        )
        == user
    )
    assert storage.get_organization(organization.id) == organization
    assert storage.get_membership(organization_id=organization.id, user_id=user.id) == membership
    listed = storage.list_user_organizations(user.id, PageParams(limit=10))
    assert [listed_org.id for listed_org in listed.items] == [organization.id]
    # ...and audit rows are proven via the duplicate-append proof (the suite
    # has no audit read surface): re-appending a provisioned aud_ id is a
    # primary-key conflict, never a silent second insert.
    for event in (first_event, second_event):
        with pytest.raises(DuplicateEntityError) as excinfo:
            storage.append_audit_event(event)
        assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID


def _provision_race_batch(
    suffix: str,
    *,
    email: str,
    provider_subject: str,
) -> tuple[User, ExternalIdentity, Organization, Membership, list[AuditEvent]]:
    """One §6 first-login attempt with per-attempt entropy: distinct
    usr_/extid_/org_/mem_/aud_ ids but a shared email and identity tuple
    (what two racing attempts actually carry)."""
    user_id = f"usr_test_{suffix}"
    organization_id = f"org_test_{suffix}"
    return (
        make_user(user_id=user_id, email=email),
        make_identity(
            identity_id=f"extid_test_{suffix}",
            user_id=user_id,
            provider_subject=provider_subject,
        ),
        make_organization(organization_id=organization_id),
        make_membership(
            membership_id=f"mem_test_{suffix}",
            organization_id=organization_id,
            user_id=user_id,
        ),
        [make_audit_event(audit_id=f"aud_test_{suffix}", organization_id=organization_id)],
    )


def test_provision_race_loser_maps_email_conflict_with_winner_id(storage: Storage) -> None:
    winner = _provision_race_batch("0001", email="race@example.test", provider_subject="sub-race")
    storage.provision_user(
        user=winner[0],
        identity=winner[1],
        organization=winner[2],
        membership=winner[3],
        audit_events=winner[4],
    )
    # Loser: same email AND same identity tuple, distinct record ids. The
    # users-email UNIQUE fires first (users insert first) and must still map
    # to the race error, not a plain email conflict.
    loser = _provision_race_batch("0002", email="race@example.test", provider_subject="sub-race")
    with pytest.raises(DuplicateExternalIdentityError) as excinfo:
        storage.provision_user(
            user=loser[0],
            identity=loser[1],
            organization=loser[2],
            membership=loser[3],
            audit_events=loser[4],
        )
    error = excinfo.value
    assert error.kind is DuplicateEntityKind.EXTERNAL_IDENTITY
    # existing_user_id resolved post-rollback from the winner's identity row.
    assert error.existing_user_id == winner[0].id
    # Full rollback: the loser consumed none of its own ids...
    with pytest.raises(EntityNotFoundError):
        storage.get_user(loser[0].id)
    with pytest.raises(EntityNotFoundError):
        storage.get_organization(loser[2].id)
    # ...including the audit id: appending it against the winner's (existing)
    # organization succeeds, proving the batch's audit row rolled back.
    assert (
        storage.append_audit_event(
            make_audit_event(audit_id=str(loser[4][0].id), organization_id=str(winner[2].id))
        )
        is None
    )
    # Winner state untouched.
    assert storage.get_user(winner[0].id) == winner[0]


def test_provision_email_collision_without_identity_resolves_by_email(storage: Storage) -> None:
    existing = make_user()
    storage.create_user(existing)
    # Email-duplicate / identity-absent variant: the identity tuple is fresh,
    # only the email collides. Same pinned mapping, with existing_user_id
    # resolved by the users-by-email fallback read.
    with pytest.raises(DuplicateExternalIdentityError) as excinfo:
        storage.provision_user(
            user=make_user(user_id="usr_test_0002", email=existing.email),
            identity=make_identity(
                identity_id="extid_test_0002",
                user_id="usr_test_0002",
                provider_subject="subject-unique-0002",
            ),
            organization=make_organization(organization_id="org_test_0002"),
            membership=make_membership(
                membership_id="mem_test_0002",
                organization_id="org_test_0002",
                user_id="usr_test_0002",
            ),
            audit_events=[
                make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0002")
            ],
        )
    assert excinfo.value.existing_user_id == existing.id
    # Full rollback: nothing but the pre-existing user survived the batch.
    with pytest.raises(EntityNotFoundError):
        storage.get_user(UserId("usr_test_0002"))
    with pytest.raises(EntityNotFoundError):
        storage.get_organization(OrganizationId("org_test_0002"))
    with pytest.raises(EntityNotFoundError):
        storage.get_user_by_external_identity(
            provider=IdentityProvider.COGNITO,
            provider_subject="subject-unique-0002",
        )
    # The rolled-back organization is genuinely absent: an audit append
    # referencing it fails on the FK (no partial org row survived).
    with pytest.raises(ReferenceNotFoundError):
        storage.append_audit_event(
            make_audit_event(audit_id="aud_test_0003", organization_id="org_test_0002")
        )
    assert storage.get_user(existing.id) == existing


def test_provision_membership_conflict_rolls_back_whole_batch(storage: Storage) -> None:
    # Pre-existing (org, user) pair that the injected membership duplicates;
    # the batch itself carries a valid (fresh) identity, user, org, and audit
    # event, so the membership pair UNIQUE is the first violation reached.
    member_user = make_user()
    member_org = make_organization()
    storage.create_user(member_user)
    storage.create_organization(member_org)
    storage.create_membership(make_membership())
    with pytest.raises(DuplicateEntityError) as excinfo:
        storage.provision_user(
            user=make_user(user_id="usr_test_0002"),
            identity=make_identity(
                identity_id="extid_test_0002",
                user_id="usr_test_0002",
                provider_subject="subject-unique-0002",
            ),
            organization=make_organization(organization_id="org_test_0002"),
            membership=make_membership(membership_id="mem_test_0002"),
            audit_events=[
                make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0002")
            ],
        )
    error = excinfo.value
    assert error.kind is DuplicateEntityKind.MEMBERSHIP
    # A membership conflict is NOT the race error: only email/identity-tuple
    # violations map to DuplicateExternalIdentityError.
    assert not isinstance(error, DuplicateExternalIdentityError)
    # No partial state: every row the batch had already written (user,
    # identity, organization) was rolled back with the rejected membership.
    with pytest.raises(EntityNotFoundError):
        storage.get_user(UserId("usr_test_0002"))
    with pytest.raises(EntityNotFoundError):
        storage.get_organization(OrganizationId("org_test_0002"))
    with pytest.raises(EntityNotFoundError):
        storage.get_user_by_external_identity(
            provider=IdentityProvider.COGNITO,
            provider_subject="subject-unique-0002",
        )
    # The batch's aud_ id survived unused: appending it against the existing
    # organization proves the audit insert rolled back too.
    assert (
        storage.append_audit_event(
            make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0001")
        )
        is None
    )
    # The pre-existing membership is untouched.
    assert (
        storage.get_membership(organization_id=member_org.id, user_id=member_user.id)
        == make_membership()
    )


def test_concurrent_identical_provisions_yield_exactly_one_success(storage: Storage) -> None:
    # §6's concurrent first login racing on a barrier (WAL + busy_timeout,
    # never sleeps): both attempts carry the same email and identity tuple
    # with distinct record ids. Exactly one commits; the other converges on
    # the race error carrying the winner's user id.
    batches = {
        "early": _provision_race_batch(
            "0002", email="race@example.test", provider_subject="sub-race"
        ),
        "late": _provision_race_batch(
            "0003", email="race@example.test", provider_subject="sub-race"
        ),
    }
    barrier = threading.Barrier(2)
    outcomes: dict[str, object] = {}

    def attempt(token: str) -> None:
        user, identity, organization, membership, audit_events = batches[token]
        try:
            barrier.wait()
            outcomes[token] = storage.provision_user(
                user=user,
                identity=identity,
                organization=organization,
                membership=membership,
                audit_events=audit_events,
            )
        except Exception as exc:  # recorded; classified on the main thread
            outcomes[token] = exc

    threads = [threading.Thread(target=attempt, args=(token,)) for token in ("early", "late")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    winner: ProvisionedUser | None = None
    loser: DuplicateExternalIdentityError | None = None
    for outcome in outcomes.values():
        if isinstance(outcome, ProvisionedUser):
            assert winner is None, "both racing provisions succeeded"
            winner = outcome
        elif isinstance(outcome, DuplicateExternalIdentityError):
            assert loser is None, "both racing provisions failed with the race error"
            loser = outcome
        else:  # pragma: no cover - fails the case on any other outcome
            raise AssertionError(f"unexpected provisioning outcome: {outcome!r}")
    assert winner is not None and loser is not None
    assert loser.existing_user_id == winner.user.id
    # Exactly one user/organization row exists: the winner's.
    assert storage.get_user(winner.user.id) == winner.user
    loser_token = "late" if winner.user.id == batches["early"][0].id else "early"
    with pytest.raises(EntityNotFoundError):
        storage.get_user(batches[loser_token][0].id)
    with pytest.raises(EntityNotFoundError):
        storage.get_organization(batches[loser_token][2].id)


# ---------------------------------------------------------------------------
# Phase 04 task 1 — provision_organization: atomic write of organization +
# membership + audits (full read-back; audit rows proven via the
# duplicate-append proof), slug conflict as a *plain* DuplicateEntityError
# (never the race error — this compound has no convergence semantics), taken
# org_/mem_/aud_ record ids as entity_id, unknown membership.user_id as
# ReferenceNotFoundError, and full rollback of every rejected batch.
# ---------------------------------------------------------------------------


def test_provision_organization_writes_every_component_atomically(storage: Storage) -> None:
    owner = make_user()
    storage.create_user(owner)
    organization = make_organization(organization_id="org_test_0002")
    membership = make_membership(
        membership_id="mem_test_0002",
        organization_id="org_test_0002",
        user_id="usr_test_0001",
    )
    first_event = make_audit_event(
        audit_id="aud_test_0002",
        organization_id="org_test_0002",
        action="organization.created",
    )
    second_event = make_audit_event(
        audit_id="aud_test_0003",
        organization_id="org_test_0002",
        action="membership.created",
        created_at=T1,
    )
    result = storage.provision_organization(
        organization=organization,
        membership=membership,
        audit_events=[first_event, second_event],
    )
    # Caller-echo contract: the bundle carries the supplied objects unchanged
    # (storage mints nothing and does not re-read what it wrote).
    assert isinstance(result, ProvisionedOrganization)
    assert result.organization == organization
    assert result.membership == membership
    assert result.audit_events == (first_event, second_event)
    # Every component is observable through its contract read path...
    assert storage.get_organization(organization.id) == organization
    assert storage.get_membership(organization_id=organization.id, user_id=owner.id) == membership
    listed = storage.list_user_organizations(owner.id, PageParams(limit=10))
    assert [listed_org.id for listed_org in listed.items] == [organization.id]
    # ...and audit rows are proven via the duplicate-append proof (the suite
    # has no audit read surface): re-appending a provisioned aud_ id is a
    # primary-key conflict, never a silent second insert.
    for event in (first_event, second_event):
        with pytest.raises(DuplicateEntityError) as excinfo:
            storage.append_audit_event(event)
        assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID


def test_provision_organization_slug_conflict_is_plain_duplicate_and_rolls_back(
    storage: Storage,
) -> None:
    owner = make_user()
    storage.create_user(owner)
    existing = make_organization()  # slug "org-org_test_0001"
    storage.create_organization(existing)
    organization = make_organization(organization_id="org_test_0002", slug=existing.slug)
    membership = make_membership(
        membership_id="mem_test_0002",
        organization_id="org_test_0002",
        user_id="usr_test_0001",
    )
    audit = make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0002")
    with pytest.raises(DuplicateEntityError) as excinfo:
        storage.provision_organization(
            organization=organization,
            membership=membership,
            audit_events=[audit],
        )
    error = excinfo.value
    assert error.kind is DuplicateEntityKind.ORGANIZATION_SLUG
    # A slug conflict is NOT the race error: this compound never converges
    # (unlike provision_user's email/identity-tuple mapping).
    assert not isinstance(error, DuplicateExternalIdentityError)
    # Full rollback: the rejected batch consumed none of its ids...
    with pytest.raises(EntityNotFoundError):
        storage.get_organization(organization.id)
    with pytest.raises(EntityNotFoundError):
        storage.get_membership(organization_id=organization.id, user_id=owner.id)
    # ...including the audit id: appending it against the *existing*
    # organization succeeds, proving the batch's audit row rolled back.
    assert (
        storage.append_audit_event(
            make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0001")
        )
        is None
    )
    # The pre-existing organization is untouched.
    assert storage.get_organization(existing.id) == existing


def test_provision_organization_taken_record_ids_raise_entity_id_conflict(
    storage: Storage,
) -> None:
    owner = make_user()
    storage.create_user(owner)
    storage.create_organization(make_organization())  # takes org_test_0001
    storage.create_membership(make_membership())  # takes mem_test_0001
    storage.append_audit_event(make_audit_event())  # takes aud_test_0001
    # Taken org_ id with a *fresh* slug (so only the record-id PK can fire).
    with pytest.raises(DuplicateEntityError) as org_conflict:
        storage.provision_organization(
            organization=make_organization(slug="fresh-slug-for-taken-id"),
            membership=make_membership(
                membership_id="mem_test_0002",
                organization_id="org_test_0001",
                user_id="usr_test_0001",
            ),
            audit_events=[
                make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0001")
            ],
        )
    assert org_conflict.value.kind is DuplicateEntityKind.ENTITY_ID
    # Taken mem_ id (fresh org id; both membership FKs pass, so the only
    # violation left is the record-id PK).
    with pytest.raises(DuplicateEntityError) as mem_conflict:
        storage.provision_organization(
            organization=make_organization(organization_id="org_test_0002"),
            membership=make_membership(
                membership_id="mem_test_0001",
                organization_id="org_test_0002",
                user_id="usr_test_0001",
            ),
            audit_events=[
                make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0002")
            ],
        )
    assert mem_conflict.value.kind is DuplicateEntityKind.ENTITY_ID
    # Taken aud_ id (fresh org/membership ids with passing FKs).
    with pytest.raises(DuplicateEntityError) as aud_conflict:
        storage.provision_organization(
            organization=make_organization(organization_id="org_test_0002"),
            membership=make_membership(
                membership_id="mem_test_0002",
                organization_id="org_test_0002",
                user_id="usr_test_0001",
            ),
            audit_events=[make_audit_event()],
        )
    assert aud_conflict.value.kind is DuplicateEntityKind.ENTITY_ID
    # Every rejected batch rolled back: only the three standalone writes
    # above exist.
    assert storage.get_organization(OrganizationId("org_test_0001")) == make_organization()
    with pytest.raises(EntityNotFoundError):
        storage.get_organization(OrganizationId("org_test_0002"))


def test_provision_organization_unknown_membership_user_raises_reference_not_found(
    storage: Storage,
) -> None:
    # The membership's user is the only parent this batch does not create;
    # the organization and audit FKs are satisfied inside the batch, so the
    # failure must name the missing user, not a phantom parent.
    organization = make_organization(organization_id="org_test_0002")
    membership = make_membership(
        membership_id="mem_test_0002",
        organization_id="org_test_0002",
        user_id="usr_ghost_0001",
    )
    audit = make_audit_event(
        audit_id="aud_test_0002",
        organization_id="org_test_0002",
        actor_user_id="usr_ghost_0001",
    )
    with pytest.raises(ReferenceNotFoundError):
        storage.provision_organization(
            organization=organization,
            membership=membership,
            audit_events=[audit],
        )
    # Full rollback: zero org/membership/audit rows from the rejected batch.
    with pytest.raises(EntityNotFoundError):
        storage.get_organization(organization.id)
    with pytest.raises(EntityNotFoundError):
        storage.get_membership(organization_id=organization.id, user_id=UserId("usr_ghost_0001"))
    with pytest.raises(ReferenceNotFoundError):
        storage.append_audit_event(audit)


# ---------------------------------------------------------------------------
# Task 8 — pagination determinism: full traversal of each list equals
# (created_at, id) order with no duplicates or skips across pages, exact-fit
# final pages report next_cursor=None, Page.limit echoes the effective
# clamped size, tampered/garbage/foreign-scope cursors raise
# InvalidCursorError, and inserts between page fetches neither duplicate nor
# skip previously unvisited items (the keyset property).
# ---------------------------------------------------------------------------


def _drain_pages[T](
    fetch: Callable[[PageParams], Page[T]],
    *,
    limit: int,
    start_cursor: str | None = None,
) -> list[Page[T]]:
    """Follow ``next_cursor`` to the end of a list and return every page.

    ``start_cursor`` lets a case resume mid-traversal with a cursor issued
    *before* later mutations (the keyset-under-insert property). Guards
    against non-termination: a cursor that loops or never resolves fails the
    case instead of hanging it.
    """
    pages: list[Page[T]] = []
    cursor: str | None = start_cursor
    for _ in range(100):
        page = fetch(PageParams(limit=limit, cursor=cursor))
        pages.append(page)
        if page.next_cursor is None:
            return pages
        cursor = page.next_cursor
    raise AssertionError("cursor traversal did not terminate within 100 pages")


def test_user_organizations_full_traversal_matches_keyset_order(storage: Storage) -> None:
    user = make_user()
    storage.create_user(user)
    organizations = (
        make_organization(organization_id="org_test_0001", created_at=T0),
        make_organization(organization_id="org_test_0002", created_at=T1),
        make_organization(organization_id="org_test_0003", created_at=T1),
        make_organization(organization_id="org_test_0004", created_at=T2),
        make_organization(organization_id="org_test_0005", created_at=T3),
    )
    for organization in organizations:
        storage.create_organization(organization)
    for index, organization in enumerate(organizations, start=1):
        storage.create_membership(
            make_membership(
                membership_id=f"mem_test_{index:04d}",
                organization_id=str(organization.id),
                user_id="usr_test_0001",
            )
        )
    # A suspended membership must hide its organization on *every* page, not
    # just the first: org_test_0006 shares T3 with org_test_0005, so a leak
    # would land mid-traversal rather than at a page boundary.
    storage.create_organization(make_organization(organization_id="org_test_0006", created_at=T3))
    storage.create_membership(
        make_membership(
            membership_id="mem_test_0006",
            organization_id="org_test_0006",
            user_id="usr_test_0001",
            status=MembershipStatus.DISABLED,
        )
    )
    pages = _drain_pages(
        lambda page: storage.list_user_organizations(user.id, page),
        limit=2,
    )
    ids = [organization.id for page in pages for organization in page.items]
    # (created_at, id) ascending: the T1 pair tie-breaks by id, and T3 sorts
    # *before* T2 (zero-µs vs microsecond in the same second) — traversal
    # order deliberately differs from both insertion and id order.
    assert ids == [
        OrganizationId("org_test_0001"),
        OrganizationId("org_test_0002"),
        OrganizationId("org_test_0003"),
        OrganizationId("org_test_0005"),
        OrganizationId("org_test_0004"),
    ]
    assert len(ids) == len(set(ids)), "pages overlapped: an item was visited twice"
    assert [len(page.items) for page in pages] == [2, 2, 1]
    assert all(page.limit == 2 for page in pages)
    assert pages[-1].next_cursor is None


def test_memberships_full_traversal_matches_keyset_order_with_exact_final_page(
    storage: Storage,
) -> None:
    organization = make_organization()
    storage.create_organization(organization)
    for index in (1, 2, 3, 4):
        storage.create_user(make_user(user_id=f"usr_test_{index:04d}"))
    storage.create_membership(make_membership(membership_id="mem_test_0001", created_at=T1))
    storage.create_membership(
        make_membership(membership_id="mem_test_0002", user_id="usr_test_0002", created_at=T0)
    )
    storage.create_membership(
        make_membership(membership_id="mem_test_0003", user_id="usr_test_0003", created_at=T0)
    )
    storage.create_membership(
        make_membership(membership_id="mem_test_0004", user_id="usr_test_0004", created_at=T2)
    )
    pages = _drain_pages(
        lambda page: storage.list_memberships(organization.id, page),
        limit=2,
    )
    ids = [membership.id for page in pages for membership in page.items]
    # T0 pair tie-broken by id, then T1, then T2 — not mem_ id order.
    assert ids == [
        MembershipId("mem_test_0002"),
        MembershipId("mem_test_0003"),
        MembershipId("mem_test_0001"),
        MembershipId("mem_test_0004"),
    ]
    # Exact-multiple data set: the final page is full, so the limit+1 probe
    # found nothing and it must still report next_cursor=None.
    assert [len(page.items) for page in pages] == [2, 2]
    assert all(page.limit == 2 for page in pages)
    assert pages[-1].next_cursor is None


def test_api_keys_full_traversal_matches_keyset_order(storage: Storage) -> None:
    _seed_key_owner(storage)
    keys = (
        make_api_key(key_id="key_test_0001", credential_segment="01JSEG0001", created_at=T2),
        make_api_key(key_id="key_test_0002", credential_segment="01JSEG0002", created_at=T0),
        make_api_key(key_id="key_test_0003", credential_segment="01JSEG0003", created_at=T0),
        make_api_key(key_id="key_test_0004", credential_segment="01JSEG0004", created_at=T3),
        make_api_key(key_id="key_test_0005", credential_segment="01JSEG0005", created_at=T4),
    )
    for api_key in keys:
        storage.create_api_key(api_key)
    pages = _drain_pages(
        lambda page: storage.list_api_keys(OrganizationId("org_test_0001"), page),
        limit=2,
    )
    ids = [api_key.id for page in pages for api_key in page.items]
    # T0 tie (id order), then T3 (zero-µs, sorts before T2's same-second
    # microsecond value), then T2, then T4.
    assert ids == [
        ApiKeyId("key_test_0002"),
        ApiKeyId("key_test_0003"),
        ApiKeyId("key_test_0004"),
        ApiKeyId("key_test_0001"),
        ApiKeyId("key_test_0005"),
    ]
    assert len(ids) == len(set(ids))
    assert all(page.limit == 2 for page in pages)
    assert pages[-1].next_cursor is None


def test_page_limit_echoes_the_effective_clamped_size(storage: Storage) -> None:
    _seed_key_owner(storage)
    for index in (1, 2, 3):
        storage.create_api_key(
            make_api_key(
                key_id=f"key_test_{index:04d}",
                credential_segment=f"01JSEG{index:04d}",
                created_at=T1,
            )
        )
    oversized = storage.list_api_keys(
        OrganizationId("org_test_0001"),
        PageParams(limit=MAX_PAGE_LIMIT + 400),
    )
    assert oversized.limit == MAX_PAGE_LIMIT
    assert len(oversized.items) == 3
    assert oversized.next_cursor is None
    undersized = storage.list_api_keys(
        OrganizationId("org_test_0001"),
        PageParams(limit=MIN_PAGE_LIMIT - 1),
    )
    assert undersized.limit == MIN_PAGE_LIMIT
    assert len(undersized.items) == MIN_PAGE_LIMIT
    assert undersized.next_cursor is not None


def _seed_two_pages_per_list(storage: Storage) -> None:
    """Seed one user, two organizations, memberships, and two API keys so
    every list can issue a first-page cursor with ``limit=1``."""
    storage.create_user(make_user())
    storage.create_user(make_user(user_id="usr_test_0002"))
    storage.create_organization(make_organization(organization_id="org_test_0001", created_at=T0))
    storage.create_organization(make_organization(organization_id="org_test_0002", created_at=T1))
    storage.create_membership(make_membership())
    storage.create_membership(
        make_membership(membership_id="mem_test_0002", organization_id="org_test_0002")
    )
    storage.create_membership(
        make_membership(
            membership_id="mem_test_0003",
            organization_id="org_test_0001",
            user_id="usr_test_0002",
        )
    )
    storage.create_api_key(make_api_key(key_id="key_test_0001", credential_segment="01JSEG0001"))
    storage.create_api_key(make_api_key(key_id="key_test_0002", credential_segment="01JSEG0002"))


def _list_fetchers(
    storage: Storage,
) -> dict[str, Callable[[PageParams], Page[object]]]:
    """The three paginated contract lists, keyed by name, for cursor cases."""
    return {
        "user_organizations": lambda page: storage.list_user_organizations(
            UserId("usr_test_0001"), page
        ),
        "memberships": lambda page: storage.list_memberships(OrganizationId("org_test_0001"), page),
        "api_keys": lambda page: storage.list_api_keys(OrganizationId("org_test_0001"), page),
    }


def test_garbage_and_tampered_cursors_raise_invalid_cursor(storage: Storage) -> None:
    _seed_two_pages_per_list(storage)
    cursor = storage.list_memberships(
        OrganizationId("org_test_0001"),
        PageParams(limit=1),
    ).next_cursor
    assert cursor is not None
    bad_tokens = (
        "not-a-cursor-!!!",  # not even base64url text
        "AAAAAAAA",  # valid base64url, decodes to non-JSON bytes
        cursor[:-4],  # truncated real cursor: the payload can no longer parse
    )
    for fetch in _list_fetchers(storage).values():
        for token in bad_tokens:
            with pytest.raises(InvalidCursorError):
                fetch(PageParams(limit=1, cursor=token))


def test_cursors_are_list_scoped_across_all_lists(storage: Storage) -> None:
    _seed_two_pages_per_list(storage)
    fetchers = _list_fetchers(storage)
    cursors = {name: fetch(PageParams(limit=1)).next_cursor for name, fetch in fetchers.items()}
    assert all(cursor is not None for cursor in cursors.values())
    # A cursor issued for one list is invalid for another (list-scope tag):
    # every cross-list combination raises, including memberships cursor ->
    # list_api_keys named by the breakdown.
    for source, cursor in cursors.items():
        for target, fetch in fetchers.items():
            if target == source:
                continue
            with pytest.raises(InvalidCursorError):
                fetch(PageParams(limit=1, cursor=cursor))


def test_inserts_between_pages_neither_duplicate_nor_skip_unvisited_items(
    storage: Storage,
) -> None:
    organization = make_organization()
    storage.create_organization(organization)
    timestamps = [datetime(2026, 9, 12, 10 + index, 0, 0, tzinfo=UTC) for index in range(5)]
    for index in range(5):
        user_id = f"usr_test_{index + 1:04d}"
        storage.create_user(make_user(user_id=user_id))
        storage.create_membership(
            make_membership(
                membership_id=f"mem_test_{index + 1:04d}",
                user_id=user_id,
                created_at=timestamps[index],
            )
        )
    first = storage.list_memberships(organization.id, PageParams(limit=2))
    assert [membership.id for membership in first.items] == [
        MembershipId("mem_test_0001"),
        MembershipId("mem_test_0002"),
    ]
    assert first.next_cursor is not None
    # Two rows land *after* the cursor but before the next unvisited item —
    # the classic offset-pagination trap: continuing from the stale cursor
    # with an offset-based page 2 would now skip one of the previously
    # unvisited originals.
    for index in (6, 7):
        user_id = f"usr_test_{index:04d}"
        storage.create_user(make_user(user_id=user_id))
        storage.create_membership(
            make_membership(
                membership_id=f"mem_test_{index:04d}",
                user_id=user_id,
                created_at=timestamps[1] + timedelta(seconds=index - 5),
            )
        )
    # Continue with the cursor issued *before* the inserts: every previously
    # unvisited original is still reached exactly once in (created_at, id)
    # order, the already-visited first page is not re-delivered, and the new
    # rows appear at their sorted positions.
    pages = _drain_pages(
        lambda page: storage.list_memberships(organization.id, page),
        limit=2,
        start_cursor=first.next_cursor,
    )
    continuation = [membership.id for page in pages for membership in page.items]
    assert continuation == [
        MembershipId("mem_test_0006"),
        MembershipId("mem_test_0007"),
        MembershipId("mem_test_0003"),
        MembershipId("mem_test_0004"),
        MembershipId("mem_test_0005"),
    ]
    assert pages[-1].next_cursor is None
    visited = [membership.id for membership in first.items] + continuation
    assert len(visited) == len(set(visited)), "an item was visited on two pages"
