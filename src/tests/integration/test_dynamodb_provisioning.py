"""DynamoDB Local proofs for audit append and the provisioning compounds (tasks 6-7).

Marker-gated (``dynamodb_local``): every test here skips with an explicit reason
unless ``FEEDNOW_DYNAMODB_LOCAL_ENDPOINT`` is set and reachable, so the default
suite stays green without Docker (``docs/operations.md`` carries the run
command).

These are **direct adapter calls**, not the conformance suite (task 8 runs the
shared 60 cases unchanged): the point is to pin the DynamoDB translation of the
8 audit/provision-user behaviors and the 4 provision-organization behaviors on
the real transactional path — the ``aud_`` native record-id conflict behind
``append_audit_event`` (with the organizations ``ConditionCheck`` replicating
the audit→org foreign key), the one-``TransactWriteItems`` shape of
``provision_user`` (decision 3: SQLite statement order, positional descriptors,
the §6 race converge resolved by one constraint-item ``GetItem`` after the
rollback, external-parent cross-checks), and ``provision_organization`` (task
7): org + slug constraint + membership (+``membership_id`` guard,
``org_created_at`` denormalization) + audits in one transaction, the users
``ConditionCheck`` for the only parent the batch never creates, a taken slug as
a **plain** duplicate (no converge, no winner read), record-id conflicts as
``entity_id``, and the caller-echo return. And — by scanning the tables
directly after every failure path — that a rejected batch leaves **zero**
residue. Domain inputs come from the suite's own deterministic builders so the
fixtures match the conformance cases exactly. Every failure asserts the domain
error *class*, the conflict *kind*, an echo-free message, and the winner's
identity where the contract pins it.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Any, get_protocol_members

import pytest
from storage_contract.suite import (
    T0,
    T1,
    make_audit_event,
    make_identity,
    make_membership,
    make_organization,
    make_user,
)

from app.models.audit_event import AuditEvent, AuditEventId
from app.models.enums import IdentityProvider
from app.models.external_identity import ExternalIdentity
from app.models.ids import OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.pagination import PageParams
from app.models.user import User
from app.storage.contract import (
    DuplicateEntityError,
    DuplicateEntityKind,
    DuplicateExternalIdentityError,
    EntityNotFoundError,
    ProvisionedOrganization,
    ProvisionedUser,
    ReferenceNotFoundError,
    Storage,
)
from app.storage.dynamodb import (
    SCHEMA,
    ConstraintKind,
    DynamoDbStorage,
    encode_constraint_key,
    encode_external_identity_value,
    encode_sort_key,
    encode_timestamp,
)
from tests.support import dynamodb_local as local

pytestmark = pytest.mark.dynamodb_local

# ---------------------------------------------------------------------------
# Harness: one fresh set of seven tables per test (the suite's isolation rule),
# plus raw scans that bypass the adapter under test so residue proofs cannot be
# satisfied by the same code path they audit. The adapter gets its **own** boto3
# resource so ``close()`` in teardown cannot take the harness client with it.
# ---------------------------------------------------------------------------


class _LocalTables:
    """Raw access to one prefixed table set (bypasses the adapter entirely)."""

    def __init__(self, resource: Any, prefix: str) -> None:
        self._resource = resource
        self.prefix = prefix

    def items(self, table: str) -> list[dict[str, Any]]:
        """Every item in one table, strongly consistent."""
        scan = self._resource.Table(f"{self.prefix}{table}").scan(ConsistentRead=True)
        items: list[dict[str, Any]] = list(scan["Items"])
        while scan.get("LastEvaluatedKey"):
            scan = self._resource.Table(f"{self.prefix}{table}").scan(
                ConsistentRead=True, ExclusiveStartKey=scan["LastEvaluatedKey"]
            )
            items.extend(scan["Items"])
        return items

    def item(self, table: str, key: Mapping[str, str]) -> dict[str, Any] | None:
        """One item by full primary key, or ``None`` when absent."""
        response = self._resource.Table(f"{self.prefix}{table}").get_item(
            Key=dict(key), ConsistentRead=True
        )
        item: dict[str, Any] | None = response.get("Item")
        return item


class _DynamoDb:
    """The adapter under test plus its raw table view."""

    def __init__(self, storage: DynamoDbStorage, tables: _LocalTables) -> None:
        self.storage = storage
        self.tables = tables

    def assert_no_leak(self, error: Exception) -> None:
        """No table name, prefix, or driver text may reach a domain message."""
        text = str(error)
        assert self.tables.prefix not in text
        for spec in SCHEMA:
            assert f"{self.tables.prefix}{spec.name}" not in text
        assert "dynamodb" not in text.lower()


@pytest.fixture
def ddb() -> Iterator[_DynamoDb]:
    """Initialized adapter with all seven tables empty (per test)."""
    endpoint = local.require_local_endpoint()
    harness = local.make_dynamodb_resource(endpoint)
    prefix = local.random_table_prefix()
    local.create_tables(prefix, resource=harness)
    storage = local.make_dynamodb_storage(prefix, resource=local.make_dynamodb_resource(endpoint))
    try:
        yield _DynamoDb(storage, _LocalTables(harness, prefix))
    finally:
        storage.close()
        local.delete_tables(prefix, resource=harness)


# ---------------------------------------------------------------------------
# Provisioning-batch helpers: the suite's race-batch shape (distinct record ids
# per attempt, shared email + identity tuple) and raw-scan residue proofs.
# ---------------------------------------------------------------------------

type _RaceBatch = tuple[User, ExternalIdentity, Organization, Membership, list[AuditEvent]]


def _race_batch(suffix: str, *, email: str, provider_subject: str) -> _RaceBatch:
    """One §6 first-login attempt, mirroring the suite's ``_provision_race_batch``."""
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


def _provision(ddb: _DynamoDb, batch: _RaceBatch) -> ProvisionedUser:
    user, identity, organization, membership, events = batch
    return ddb.storage.provision_user(
        user=user,
        identity=identity,
        organization=organization,
        membership=membership,
        audit_events=events,
    )


def _constraint_pks(
    user: User,
    identity: ExternalIdentity,
    organization: Organization,
    membership: Membership,
) -> dict[str, str]:
    """The four constraint PKs a ``provision_user`` batch writes, by kind."""
    return {
        ConstraintKind.USER_EMAIL.value: encode_constraint_key(
            ConstraintKind.USER_EMAIL, user.email
        ),
        ConstraintKind.EXTERNAL_IDENTITY.value: encode_constraint_key(
            ConstraintKind.EXTERNAL_IDENTITY,
            encode_external_identity_value(
                identity.provider, identity.provider_subject, identity.provider_tenant
            ),
        ),
        ConstraintKind.ORGANIZATION_SLUG.value: encode_constraint_key(
            ConstraintKind.ORGANIZATION_SLUG, organization.slug
        ),
        ConstraintKind.MEMBERSHIP_ID.value: encode_constraint_key(
            ConstraintKind.MEMBERSHIP_ID, str(membership.id)
        ),
    }


def _assert_batch_absent(
    ddb: _DynamoDb,
    batch: _RaceBatch,
    *,
    expect_pair_gone: bool = True,
    shared_kinds: tuple[ConstraintKind, ...] = (),
) -> None:
    """Direct table scans: the rejected batch consumed none of its own ids.

    ``shared_kinds`` names constraint kinds whose PK is deliberately the same
    as another batch's — the §6 race carries one email and identity tuple
    across winner and loser, so those items must map to the *winner* (pinned
    by the caller), not be absent.
    """
    user, identity, organization, membership, events = batch
    assert ddb.tables.item("users", {"pk": str(user.id)}) is None
    assert ddb.tables.item("external_identities", {"pk": str(identity.id)}) is None
    assert ddb.tables.item("organizations", {"pk": str(organization.id)}) is None
    if expect_pair_gone:
        # The membership base key is the (org, user) pair; a batch whose pair
        # duplicates a pre-existing membership keeps that row (it was never
        # the batch's to roll back), so callers pin the pair separately.
        assert (
            ddb.tables.item(
                "memberships",
                {
                    "organization_id": str(membership.organization_id),
                    "user_id": str(membership.user_id),
                },
            )
            is None
        )
    for event in events:
        assert ddb.tables.item("audit_events", {"pk": str(event.id)}) is None
    for kind, pk in _constraint_pks(user, identity, organization, membership).items():
        if ConstraintKind(kind) in shared_kinds:
            continue
        assert ddb.tables.item("unique_constraints", {"pk": pk}) is None


def _assert_all_tables_empty(ddb: _DynamoDb) -> None:
    """Zero-residue across the whole seven-table schema."""
    for spec in SCHEMA:
        assert ddb.tables.items(spec.name) == []


def _org_constraint_pks(
    organization: Organization,
    membership: Membership,
) -> dict[str, str]:
    """The two constraint PKs a ``provision_organization`` batch writes, by kind."""
    return {
        ConstraintKind.ORGANIZATION_SLUG.value: encode_constraint_key(
            ConstraintKind.ORGANIZATION_SLUG, organization.slug
        ),
        ConstraintKind.MEMBERSHIP_ID.value: encode_constraint_key(
            ConstraintKind.MEMBERSHIP_ID, str(membership.id)
        ),
    }


def _assert_org_batch_absent(
    ddb: _DynamoDb,
    organization: Organization,
    membership: Membership,
    events: Sequence[AuditEvent],
    *,
    expect_org_gone: bool = True,
    expect_pair_gone: bool = True,
    expect_audits_gone: bool = True,
    shared_kinds: Iterable[ConstraintKind] = (),
) -> None:
    """Direct table scans: the rejected organization batch consumed none of its
    own ids (the DynamoDB analogue of SQLite's full rollback).

    The ``expect_*_gone=False`` flags mark a record whose id the batch
    deliberately shares with a pre-existing row (a taken ``org_`` id, a taken
    ``(org, user)`` pair, a taken ``aud_`` id): that row belongs to the setup,
    not the batch, so it stays. ``shared_kinds`` names constraint kinds owned
    by another row (a taken slug maps to its original owner; a taken ``mem_``
    guard belongs to the pre-existing membership); callers pin those
    separately instead of asserting absence.
    """
    shared = frozenset(shared_kinds)
    if expect_org_gone:
        assert ddb.tables.item("organizations", {"pk": str(organization.id)}) is None
    if expect_pair_gone:
        assert (
            ddb.tables.item(
                "memberships",
                {
                    "organization_id": str(membership.organization_id),
                    "user_id": str(membership.user_id),
                },
            )
            is None
        )
    if expect_audits_gone:
        for event in events:
            assert ddb.tables.item("audit_events", {"pk": str(event.id)}) is None
    for kind, pk in _org_constraint_pks(organization, membership).items():
        if ConstraintKind(kind) in shared:
            continue
        assert ddb.tables.item("unique_constraints", {"pk": pk}) is None


def _provision_org(
    ddb: _DynamoDb,
    organization: Organization,
    membership: Membership,
    events: Sequence[AuditEvent],
) -> ProvisionedOrganization:
    return ddb.storage.provision_organization(
        organization=organization,
        membership=membership,
        audit_events=events,
    )


# ---------------------------------------------------------------------------
# Audit append: returns None, native aud_ conflict, audit→org ConditionCheck
# ---------------------------------------------------------------------------


def test_append_audit_event_returns_none_and_stores_native_item(ddb: _DynamoDb) -> None:
    ddb.storage.create_organization(make_organization())
    event = make_audit_event()
    # Contract-pinned: append returns ``None`` — storage mints nothing and
    # re-reads nothing, so there is nothing to return.
    assert ddb.storage.append_audit_event(event) is None
    raw = ddb.tables.item("audit_events", {"pk": str(event.id)})
    assert raw is not None
    assert raw["organization_id"] == str(event.organization_id)
    assert raw["actor_type"] == event.actor_type
    assert raw["actor_id"] == str(event.actor_id)
    assert raw["action"] == event.action
    assert raw["created_at"] == encode_timestamp(event.created_at)
    # Decision 6: metadata is a native M, not JSON text; optional target
    # fields are absent attributes when None (the api-key convention).
    assert raw["metadata"] == {"conformance": True}
    assert "target_type" not in raw and "target_id" not in raw
    # A targeted event with nested metadata stores the fields it carries.
    targeted = AuditEvent(
        id=AuditEventId("aud_test_0002"),
        organization_id=OrganizationId("org_test_0001"),
        actor_type="user",
        actor_id=UserId("usr_test_0001"),
        action="membership.created",
        target_type="membership",
        target_id="mem_test_0001",
        metadata={"role": "owner", "nested": [1, {"ok": True}], "note": None},
        created_at=T1,
    )
    assert ddb.storage.append_audit_event(targeted) is None
    raw_targeted = ddb.tables.item("audit_events", {"pk": "aud_test_0002"})
    assert raw_targeted is not None
    assert raw_targeted["target_type"] == "membership"
    assert raw_targeted["target_id"] == "mem_test_0001"
    assert raw_targeted["metadata"] == {"role": "owner", "nested": [1, {"ok": True}], "note": None}


def test_duplicate_audit_append_raises_entity_id_conflict(ddb: _DynamoDb) -> None:
    ddb.storage.create_organization(make_organization())
    ddb.storage.append_audit_event(make_audit_event())
    # Second append of the same aud_ id: with no read surface, this rejection
    # is the persistence proof — and the aud_ record id is native on the base
    # table (decision 2), so the condition failure maps to kind="entity_id".
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.append_audit_event(make_audit_event())
    assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID
    ddb.assert_no_leak(excinfo.value)
    # The rejected append is fully rolled back: the adapter stays usable and
    # a fresh event under a new aud_ id still appends.
    assert ddb.storage.append_audit_event(make_audit_event(audit_id="aud_test_0002")) is None
    assert len(ddb.tables.items("audit_events")) == 2


def test_audit_event_for_unknown_organization_raises_reference_not_found(
    ddb: _DynamoDb,
) -> None:
    # audit→organization is the only parent an audit row references (the actor
    # id is §10 application identity, not an FK). DynamoDB has no foreign keys:
    # the organizations ConditionCheck replicates SQLite's FK enforcement.
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        ddb.storage.append_audit_event(make_audit_event(organization_id="org_ghost_0001"))
    ddb.assert_no_leak(excinfo.value)
    assert ddb.tables.items("audit_events") == []


# ---------------------------------------------------------------------------
# provision_user happy path: one transaction, every component observable,
# constraint items and the denormalized membership sort key written
# ---------------------------------------------------------------------------


def test_provision_user_writes_every_component_atomically(ddb: _DynamoDb) -> None:
    user = make_user()
    identity = make_identity(user_id="usr_test_0001")
    organization = make_organization()
    membership = make_membership()
    first_event = make_audit_event(audit_id="aud_test_0001")
    second_event = make_audit_event(
        audit_id="aud_test_0002", action="organization.created", created_at=T1
    )
    result = ddb.storage.provision_user(
        user=user,
        identity=identity,
        organization=organization,
        membership=membership,
        audit_events=[first_event, second_event],
    )
    # Caller-echo contract: the bundle carries the supplied objects unchanged.
    assert isinstance(result, ProvisionedUser)
    assert result.user == user
    assert result.identity == identity
    assert result.organization == organization
    assert result.membership == membership
    assert result.audit_events == (first_event, second_event)
    # Every component is observable through its contract read path...
    assert ddb.storage.get_user(user.id) == user
    assert (
        ddb.storage.get_user_by_external_identity(
            provider=identity.provider,
            provider_subject=identity.provider_subject,
        )
        == user
    )
    assert ddb.storage.get_organization(organization.id) == organization
    assert ddb.storage.get_membership(organization_id=organization.id, user_id=user.id) == (
        membership
    )
    listed = ddb.storage.list_user_organizations(user.id, PageParams(limit=10))
    assert [listed_org.id for listed_org in listed.items] == [organization.id]
    # The membership item carries the *batch's* organization created_at on the
    # by-user sort key (decision 2: the compound constructs the org, no read).
    raw_membership = ddb.tables.item(
        "memberships",
        {"organization_id": str(organization.id), "user_id": str(user.id)},
    )
    assert raw_membership is not None
    assert raw_membership["g_user"] == str(user.id)
    assert raw_membership["g_org_created"] == encode_sort_key(
        organization.created_at, str(organization.id)
    )
    # All four constraint items went in the same transaction; the email and
    # identity-tuple items carry user_id — what race resolution reads.
    pks = _constraint_pks(user, identity, organization, membership)
    email_item = ddb.tables.item("unique_constraints", {"pk": pks["user_email"]})
    assert email_item is not None
    assert email_item["user_id"] == str(user.id)
    identity_item = ddb.tables.item("unique_constraints", {"pk": pks["external_identity"]})
    assert identity_item is not None
    assert identity_item["user_id"] == str(user.id)
    slug_item = ddb.tables.item("unique_constraints", {"pk": pks["organization_slug"]})
    assert slug_item is not None
    assert slug_item["entity_id"] == str(organization.id)
    membership_guard = ddb.tables.item("unique_constraints", {"pk": pks["membership_id"]})
    assert membership_guard is not None
    assert membership_guard["entity_id"] == str(membership.id)
    # ...and audit rows are proven via the duplicate-append proof (the suite
    # has no audit read surface): re-appending a provisioned aud_ id is a
    # primary-key conflict, never a silent second insert.
    for event in (first_event, second_event):
        with pytest.raises(DuplicateEntityError) as excinfo:
            ddb.storage.append_audit_event(event)
        assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID


# ---------------------------------------------------------------------------
# provision_user conflicts: §6 race converge (winner id resolved), email-only
# collision, membership-pair plain conflict — every path zero-residue
# ---------------------------------------------------------------------------


def test_provision_race_loser_maps_email_conflict_with_winner_id(ddb: _DynamoDb) -> None:
    winner = _race_batch("0001", email="race@example.test", provider_subject="sub-race")
    _provision(ddb, winner)
    # Loser: same email AND same identity tuple, distinct record ids. The
    # users-email constraint fails first in submission order (SQLite statement
    # order) and must still map to the race error, not a plain email conflict.
    loser = _race_batch("0002", email="race@example.test", provider_subject="sub-race")
    with pytest.raises(DuplicateExternalIdentityError) as excinfo:
        _provision(ddb, loser)
    error = excinfo.value
    assert error.kind is DuplicateEntityKind.EXTERNAL_IDENTITY
    ddb.assert_no_leak(error)
    # existing_user_id resolved post-rollback by one GetItem on the winning
    # email-constraint item — which still maps to the winner, untouched.
    assert error.existing_user_id == winner[0].id
    constraint = ddb.tables.item(
        "unique_constraints",
        {"pk": encode_constraint_key(ConstraintKind.USER_EMAIL, "race@example.test")},
    )
    assert constraint is not None
    assert constraint["user_id"] == str(winner[0].id)
    tuple_constraint = ddb.tables.item(
        "unique_constraints",
        {
            "pk": encode_constraint_key(
                ConstraintKind.EXTERNAL_IDENTITY,
                encode_external_identity_value(
                    winner[1].provider, winner[1].provider_subject, None
                ),
            )
        },
    )
    assert tuple_constraint is not None
    assert tuple_constraint["user_id"] == str(winner[0].id)
    # Full rollback: the loser consumed none of its own ids (direct scans).
    # The email and identity-tuple constraint PKs are shared with the winner
    # (that is what the race carries), so they are pinned to the winner above.
    _assert_batch_absent(
        ddb,
        loser,
        shared_kinds=(ConstraintKind.USER_EMAIL, ConstraintKind.EXTERNAL_IDENTITY),
    )
    # ...including the audit id: appending it against the winner's (existing)
    # organization succeeds, proving the batch's audit row rolled back.
    assert (
        ddb.storage.append_audit_event(
            make_audit_event(audit_id=str(loser[4][0].id), organization_id=str(winner[2].id))
        )
        is None
    )
    # Winner state untouched.
    assert ddb.storage.get_user(winner[0].id) == winner[0]


def test_provision_email_collision_without_identity_resolves_by_email(ddb: _DynamoDb) -> None:
    existing = make_user()
    ddb.storage.create_user(existing)
    # Email-duplicate / identity-absent variant: the identity tuple is fresh,
    # only the email constraint collides. Same pinned converge mapping, with
    # existing_user_id resolved from the winning email-constraint item.
    with pytest.raises(DuplicateExternalIdentityError) as excinfo:
        ddb.storage.provision_user(
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
    ddb.assert_no_leak(excinfo.value)
    # Full rollback: nothing but the pre-existing user (and its email
    # constraint) survived the batch — proven by direct scans, not the adapter.
    assert len(ddb.tables.items("users")) == 1
    assert ddb.tables.items("external_identities") == []
    assert ddb.tables.items("organizations") == []
    assert ddb.tables.items("memberships") == []
    assert ddb.tables.items("audit_events") == []
    assert len(ddb.tables.items("unique_constraints")) == 1
    with pytest.raises(EntityNotFoundError):
        ddb.storage.get_user_by_external_identity(
            provider=IdentityProvider.COGNITO,
            provider_subject="subject-unique-0002",
        )
    # The rolled-back organization is genuinely absent: an audit append
    # referencing it fails on the ConditionCheck (no partial org row survived).
    with pytest.raises(ReferenceNotFoundError):
        ddb.storage.append_audit_event(
            make_audit_event(audit_id="aud_test_0003", organization_id="org_test_0002")
        )
    assert ddb.storage.get_user(existing.id) == existing


def test_provision_membership_conflict_rolls_back_whole_batch(ddb: _DynamoDb) -> None:
    # Pre-existing (org, user) pair that the injected membership duplicates;
    # the batch itself carries a valid (fresh) identity, user, org, and audit
    # event, so the membership pair condition is the first failure reached.
    member_user = make_user()
    member_org = make_organization()
    ddb.storage.create_user(member_user)
    ddb.storage.create_organization(member_org)
    ddb.storage.create_membership(make_membership())
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.provision_user(
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
    ddb.assert_no_leak(error)
    # A membership conflict is NOT the race error: only email/identity-tuple
    # violations map to DuplicateExternalIdentityError, and it carries no
    # existing_user_id resolution.
    assert not isinstance(error, DuplicateExternalIdentityError)
    # No partial state: every row the batch had already written (user,
    # identity, organization) was rolled back with the rejected membership —
    # the pair itself is pre-existing, so it belongs to the setup, not the batch.
    _assert_batch_absent(
        ddb,
        (
            make_user(user_id="usr_test_0002"),
            make_identity(
                identity_id="extid_test_0002",
                user_id="usr_test_0002",
                provider_subject="subject-unique-0002",
            ),
            make_organization(organization_id="org_test_0002"),
            make_membership(membership_id="mem_test_0002"),
            [make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0002")],
        ),
        expect_pair_gone=False,
    )
    # The batch's aud_ id survived unused: appending it against the existing
    # organization proves the audit insert rolled back too.
    assert (
        ddb.storage.append_audit_event(
            make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0001")
        )
        is None
    )
    # The pre-existing membership is untouched (the conflict never overwrote it).
    assert ddb.storage.get_membership(organization_id=member_org.id, user_id=member_user.id) == (
        make_membership()
    )


def test_provision_slug_conflict_is_plain_duplicate_and_rolls_back(ddb: _DynamoDb) -> None:
    # The batch's own email/identity/user/pair are all fresh; only the slug is
    # taken by another organization. Inside provision_user a slug failure is
    # NOT the race converge — it propagates as its own DuplicateEntityError
    # kind (the compound's "other kinds propagate correctly" obligation).
    ddb.storage.create_organization(
        make_organization(organization_id="org_test_0009", slug="org-org_test_0002")
    )
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.provision_user(
            user=make_user(user_id="usr_test_0002"),
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
    error = excinfo.value
    assert error.kind is DuplicateEntityKind.ORGANIZATION_SLUG
    assert not isinstance(error, DuplicateExternalIdentityError)
    ddb.assert_no_leak(error)
    # Full rollback, and the taken slug still maps to its original owner.
    _assert_batch_absent(
        ddb,
        (
            make_user(user_id="usr_test_0002"),
            make_identity(
                identity_id="extid_test_0002",
                user_id="usr_test_0002",
                provider_subject="subject-unique-0002",
            ),
            make_organization(organization_id="org_test_0002"),
            make_membership(
                membership_id="mem_test_0002",
                organization_id="org_test_0002",
                user_id="usr_test_0002",
            ),
            [make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0002")],
        ),
        # The slug constraint PK is the pre-existing owner's (pinned below).
        shared_kinds=(ConstraintKind.ORGANIZATION_SLUG,),
    )
    slug_item = ddb.tables.item(
        "unique_constraints",
        {"pk": encode_constraint_key(ConstraintKind.ORGANIZATION_SLUG, "org-org_test_0002")},
    )
    assert slug_item is not None
    assert slug_item["entity_id"] == "org_test_0009"


def test_concurrent_identical_provisions_yield_exactly_one_success(ddb: _DynamoDb) -> None:
    # §6's concurrent first login racing on a barrier (never sleeps): both
    # attempts carry the same email and identity tuple with distinct record
    # ids. TransactWriteItems serializes them (decision 9): exactly one
    # commits; the other converges on the race error carrying the winner's id.
    batches = {
        "early": _race_batch("0002", email="race@example.test", provider_subject="sub-race"),
        "late": _race_batch("0003", email="race@example.test", provider_subject="sub-race"),
    }
    barrier = threading.Barrier(2)
    outcomes: dict[str, object] = {}

    def attempt(token: str) -> None:
        try:
            barrier.wait()
            outcomes[token] = _provision(ddb, batches[token])
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
    # Exactly one user/organization row exists: the winner's. The loser's
    # rollback is proven by direct table scans.
    loser_token = "late" if winner.user.id == batches["early"][0].id else "early"
    # The shared email/identity-tuple constraint PKs belong to the winner (the
    # race is on those values), so they are excluded from the absence scan.
    _assert_batch_absent(
        ddb,
        batches[loser_token],
        shared_kinds=(ConstraintKind.USER_EMAIL, ConstraintKind.EXTERNAL_IDENTITY),
    )
    assert ddb.storage.get_user(winner.user.id) == winner.user


# ---------------------------------------------------------------------------
# External-parent cross-checks: a parent the batch does not itself create is
# enforced by a ConditionCheck (the contract's DynamoDB FK obligation)
# ---------------------------------------------------------------------------


def test_provision_with_identity_owned_by_unknown_external_user_raises_reference_not_found(
    ddb: _DynamoDb,
) -> None:
    # identity.user_id names a user the batch does not create (it differs from
    # the batch's usr_test_0001) and does not exist: the users ConditionCheck
    # replicates SQLite's identity→user foreign key.
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        ddb.storage.provision_user(
            user=make_user(),
            identity=make_identity(user_id="usr_ghost_0001"),
            organization=make_organization(),
            membership=make_membership(),
            audit_events=[make_audit_event()],
        )
    ddb.assert_no_leak(excinfo.value)
    # The whole batch rolled back: zero residue across all seven tables.
    _assert_all_tables_empty(ddb)


def test_provision_with_audit_for_unknown_external_org_raises_reference_not_found(
    ddb: _DynamoDb,
) -> None:
    # An audit event referencing an organization outside the batch (and
    # unknown) fails the organizations ConditionCheck — the batch's own org
    # does not excuse a foreign reference (SQLite FK parity).
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        ddb.storage.provision_user(
            user=make_user(),
            identity=make_identity(user_id="usr_test_0001"),
            organization=make_organization(),
            membership=make_membership(),
            audit_events=[make_audit_event(organization_id="org_ghost_0001")],
        )
    ddb.assert_no_leak(excinfo.value)
    _assert_all_tables_empty(ddb)


def test_provision_membership_for_unknown_external_org_raises_reference_not_found(
    ddb: _DynamoDb,
) -> None:
    # The membership points at an organization outside the batch (the batch
    # creates org_test_0002) that does not exist: the pre-read that supplies
    # the true g_org_created timestamp rejects it, mirroring create_membership
    # (read informs the item, the reference check enforces existence).
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        ddb.storage.provision_user(
            user=make_user(user_id="usr_test_0002"),
            identity=make_identity(
                identity_id="extid_test_0002",
                user_id="usr_test_0002",
                provider_subject="subject-unique-0002",
            ),
            organization=make_organization(organization_id="org_test_0002"),
            membership=make_membership(
                membership_id="mem_test_0002",
                organization_id="org_ghost_0001",
                user_id="usr_test_0002",
            ),
            audit_events=[
                make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0002")
            ],
        )
    ddb.assert_no_leak(excinfo.value)
    _assert_all_tables_empty(ddb)


def test_provision_membership_for_unknown_external_user_raises_reference_not_found(
    ddb: _DynamoDb,
) -> None:
    # The membership's user is outside the batch and unknown: the users
    # ConditionCheck replicates SQLite's membership→user foreign key, and the
    # whole rejected batch leaves zero residue.
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        ddb.storage.provision_user(
            user=make_user(user_id="usr_test_0002"),
            identity=make_identity(
                identity_id="extid_test_0002",
                user_id="usr_test_0002",
                provider_subject="subject-unique-0002",
            ),
            organization=make_organization(organization_id="org_test_0002"),
            membership=make_membership(
                membership_id="mem_test_0002",
                organization_id="org_test_0002",
                user_id="usr_ghost_0001",
            ),
            audit_events=[
                make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0002")
            ],
        )
    ddb.assert_no_leak(excinfo.value)
    _assert_all_tables_empty(ddb)


def test_provision_membership_into_external_org_denormalizes_true_org_timestamp(
    ddb: _DynamoDb,
) -> None:
    # SQLite's list_user_organizations join orders by the membership's ACTUAL
    # organization created_at; the DynamoDB equivalent is the denormalized
    # g_org_created sort key. When the batch's membership points at an external
    # (existing) organization, the item must carry that org's timestamp — not
    # the batch organization's — or the listing mis-sorts (parity pin).
    external = make_organization(organization_id="org_test_0001", created_at=T1)
    ddb.storage.create_organization(external)
    batch_org = make_organization(organization_id="org_test_0002")  # created T0
    membership = make_membership(
        membership_id="mem_test_0002",
        organization_id="org_test_0001",
        user_id="usr_test_0002",
    )
    _provision(
        ddb,
        (
            make_user(user_id="usr_test_0002"),
            make_identity(
                identity_id="extid_test_0002",
                user_id="usr_test_0002",
                provider_subject="subject-unique-0002",
            ),
            batch_org,
            membership,
            [make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0002")],
        ),
    )
    raw = ddb.tables.item(
        "memberships",
        {"organization_id": "org_test_0001", "user_id": "usr_test_0002"},
    )
    assert raw is not None
    assert raw["g_org_created"] == encode_sort_key(T1, "org_test_0001")
    assert raw["g_org_created"] != encode_sort_key(T0, "org_test_0001")
    # The listing resolves the external organization with its true payload.
    listed = ddb.storage.list_user_organizations(UserId("usr_test_0002"), PageParams(limit=10))
    assert [org.id for org in listed.items] == [external.id]
    assert listed.items[0] == external


# ---------------------------------------------------------------------------
# provision_organization (task 7): one transaction for org + slug constraint +
# membership (+guard item, org_created_at denormalization) + audits; the users
# ConditionCheck enforces the only parent the batch never creates; a taken slug
# is a plain conflict (never the §6 converge); record ids map to entity_id;
# every rejected batch leaves zero residue.
# ---------------------------------------------------------------------------


def test_provision_organization_writes_every_component_atomically(ddb: _DynamoDb) -> None:
    owner = make_user()
    ddb.storage.create_user(owner)
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
    result = _provision_org(ddb, organization, membership, [first_event, second_event])
    # Caller-echo contract: the bundle carries the supplied objects unchanged
    # (storage mints nothing and does not re-read what it wrote).
    assert isinstance(result, ProvisionedOrganization)
    assert result.organization == organization
    assert result.membership == membership
    assert result.audit_events == (first_event, second_event)
    # Every component is observable through its contract read path...
    assert ddb.storage.get_organization(organization.id) == organization
    assert (
        ddb.storage.get_membership(organization_id=organization.id, user_id=owner.id) == membership
    )
    listed = ddb.storage.list_user_organizations(owner.id, PageParams(limit=10))
    assert [listed_org.id for listed_org in listed.items] == [organization.id]
    # The membership item carries the *batch's* organization created_at on the
    # by-user sort key (decision 2: the compound constructs the org, no read).
    raw_membership = ddb.tables.item(
        "memberships",
        {"organization_id": str(organization.id), "user_id": str(owner.id)},
    )
    assert raw_membership is not None
    assert raw_membership["g_user"] == str(owner.id)
    assert raw_membership["g_org_created"] == encode_sort_key(
        organization.created_at, str(organization.id)
    )
    # Both constraint items went in the same transaction: the slug guard maps
    # to the organization and the mem_ guard to the membership record id.
    pks = _org_constraint_pks(organization, membership)
    slug_item = ddb.tables.item("unique_constraints", {"pk": pks["organization_slug"]})
    assert slug_item is not None
    assert slug_item["entity_id"] == str(organization.id)
    membership_guard = ddb.tables.item("unique_constraints", {"pk": pks["membership_id"]})
    assert membership_guard is not None
    assert membership_guard["entity_id"] == str(membership.id)
    # ...and audit rows are proven via the duplicate-append proof (the suite
    # has no audit read surface): re-appending a provisioned aud_ id is a
    # primary-key conflict, never a silent second insert.
    for event in (first_event, second_event):
        with pytest.raises(DuplicateEntityError) as excinfo:
            ddb.storage.append_audit_event(event)
        assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID


def test_provision_organization_slug_conflict_is_plain_duplicate_and_rolls_back(
    ddb: _DynamoDb,
) -> None:
    owner = make_user()
    ddb.storage.create_user(owner)
    existing = make_organization()  # slug "org-org_test_0001"
    ddb.storage.create_organization(existing)
    organization = make_organization(organization_id="org_test_0002", slug=existing.slug)
    membership = make_membership(
        membership_id="mem_test_0002",
        organization_id="org_test_0002",
        user_id="usr_test_0001",
    )
    audit = make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0002")
    with pytest.raises(DuplicateEntityError) as excinfo:
        _provision_org(ddb, organization, membership, [audit])
    error = excinfo.value
    # A taken slug is a plain conflict: provision_organization has NO race
    # convergence (unlike provision_user's email/identity-tuple mapping).
    assert error.kind is DuplicateEntityKind.ORGANIZATION_SLUG
    assert not isinstance(error, DuplicateExternalIdentityError)
    ddb.assert_no_leak(error)
    # Full rollback: the rejected batch consumed none of its own ids...
    _assert_org_batch_absent(
        ddb,
        organization,
        membership,
        [audit],
        # The slug constraint PK is the pre-existing owner's (pinned below).
        shared_kinds=(ConstraintKind.ORGANIZATION_SLUG,),
    )
    # ...and the taken slug still maps to its original owner, untouched.
    slug_item = ddb.tables.item(
        "unique_constraints",
        {"pk": _org_constraint_pks(organization, membership)["organization_slug"]},
    )
    assert slug_item is not None
    assert slug_item["entity_id"] == str(existing.id)
    # The batch's audit id survived unused: appending it against the *existing*
    # organization proves the batch's audit row rolled back.
    assert (
        ddb.storage.append_audit_event(
            make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0001")
        )
        is None
    )
    assert ddb.storage.get_organization(existing.id) == existing


def test_provision_organization_taken_record_ids_raise_entity_id_conflict(
    ddb: _DynamoDb,
) -> None:
    owner = make_user()
    ddb.storage.create_user(owner)
    ddb.storage.create_organization(make_organization())  # takes org_test_0001
    ddb.storage.create_membership(make_membership())  # takes mem_test_0001
    ddb.storage.append_audit_event(make_audit_event())  # takes aud_test_0001
    # Taken org_ id with a *fresh* slug (so only the record-id PK can fire):
    # the base put is first in submission order, mirroring SQLite's statement
    # order, and the (org, user) pair is pre-existing so it belongs to setup.
    org_batch = (
        make_organization(slug="fresh-slug-for-taken-id"),
        make_membership(
            membership_id="mem_test_0002",
            organization_id="org_test_0001",
            user_id="usr_test_0001",
        ),
        [make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0001")],
    )
    with pytest.raises(DuplicateEntityError) as org_conflict:
        _provision_org(ddb, *org_batch)
    assert org_conflict.value.kind is DuplicateEntityKind.ENTITY_ID
    ddb.assert_no_leak(org_conflict.value)
    _assert_org_batch_absent(
        ddb,
        *org_batch,
        # The org id and the (org, user) pair are the setup's, not the batch's
        # to roll back; the batch's own slug/guard/audit rows are all absent.
        expect_org_gone=False,
        expect_pair_gone=False,
    )
    # Taken mem_ id (fresh org id; both membership FKs pass, so the only
    # violation left is the record-id guard item).
    mem_batch = (
        make_organization(organization_id="org_test_0002"),
        make_membership(
            membership_id="mem_test_0001",
            organization_id="org_test_0002",
            user_id="usr_test_0001",
        ),
        [make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0002")],
    )
    with pytest.raises(DuplicateEntityError) as mem_conflict:
        _provision_org(ddb, *mem_batch)
    assert mem_conflict.value.kind is DuplicateEntityKind.ENTITY_ID
    ddb.assert_no_leak(mem_conflict.value)
    _assert_org_batch_absent(
        ddb,
        *mem_batch,
        # The guard item is the pre-existing membership's (pinned below).
        shared_kinds=(ConstraintKind.MEMBERSHIP_ID,),
    )
    guard_item = ddb.tables.item(
        "unique_constraints",
        {"pk": _org_constraint_pks(mem_batch[0], mem_batch[1])["membership_id"]},
    )
    assert guard_item is not None
    assert guard_item["entity_id"] == "mem_test_0001"
    # Taken aud_ id (fresh org/membership ids with passing FKs).
    aud_batch = (
        make_organization(organization_id="org_test_0002"),
        make_membership(
            membership_id="mem_test_0002",
            organization_id="org_test_0002",
            user_id="usr_test_0001",
        ),
        [make_audit_event()],
    )
    with pytest.raises(DuplicateEntityError) as aud_conflict:
        _provision_org(ddb, *aud_batch)
    assert aud_conflict.value.kind is DuplicateEntityKind.ENTITY_ID
    ddb.assert_no_leak(aud_conflict.value)
    # The taken aud_ id belongs to the setup append, so only the fresh
    # org/membership rows and their constraint items must be gone.
    _assert_org_batch_absent(ddb, *aud_batch, expect_audits_gone=False)
    # Every rejected batch rolled back: only the three standalone writes
    # above exist.
    assert ddb.storage.get_organization(OrganizationId("org_test_0001")) == make_organization()
    with pytest.raises(EntityNotFoundError):
        ddb.storage.get_organization(OrganizationId("org_test_0002"))
    assert len(ddb.tables.items("organizations")) == 1
    assert len(ddb.tables.items("memberships")) == 1
    assert len(ddb.tables.items("audit_events")) == 1


def test_provision_organization_unknown_membership_user_raises_reference_not_found(
    ddb: _DynamoDb,
) -> None:
    # The membership's user is the only parent this batch does not create; the
    # organization and audit FKs are satisfied inside the batch, so the users
    # ConditionCheck must name the missing user, not a phantom parent.
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
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        _provision_org(ddb, organization, membership, [audit])
    ddb.assert_no_leak(excinfo.value)
    # Full rollback: zero org/membership/audit rows from the rejected batch —
    # every one of the seven tables is still empty (direct scans).
    _assert_all_tables_empty(ddb)
    # The rolled-back organization is genuinely absent: re-appending the
    # batch's audit fails on the audit→org ConditionCheck.
    with pytest.raises(ReferenceNotFoundError):
        ddb.storage.append_audit_event(audit)


def test_provision_organization_membership_into_external_org_uses_true_timestamp(
    ddb: _DynamoDb,
) -> None:
    # Same denormalization discipline as provision_user: when the batch's
    # membership points at an organization OUTSIDE the batch (the batch creates
    # org_test_0002), the by-user sort key carries the EXTERNAL org's
    # created_at — SQLite's join orders by the true org, so anything else
    # mis-sorts the listing (parity pin).
    owner = make_user()
    ddb.storage.create_user(owner)
    external = make_organization(organization_id="org_test_0001", created_at=T1)
    ddb.storage.create_organization(external)
    batch_org = make_organization(organization_id="org_test_0002")  # created T0
    membership = make_membership(
        membership_id="mem_test_0002",
        organization_id="org_test_0001",
        user_id="usr_test_0001",
    )
    _provision_org(
        ddb,
        batch_org,
        membership,
        [make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0002")],
    )
    raw = ddb.tables.item(
        "memberships",
        {"organization_id": "org_test_0001", "user_id": "usr_test_0001"},
    )
    assert raw is not None
    assert raw["g_org_created"] == encode_sort_key(T1, "org_test_0001")
    assert raw["g_org_created"] != encode_sort_key(T0, "org_test_0001")
    listed = ddb.storage.list_user_organizations(owner.id, PageParams(limit=10))
    assert [org.id for org in listed.items] == [external.id]
    assert listed.items[0] == external


def test_provision_organization_unknown_external_membership_org_raises_reference_not_found(
    ddb: _DynamoDb,
) -> None:
    # The membership points at an organization outside the batch (the batch
    # creates org_test_0002) that does not exist: the pre-read that supplies
    # the true g_org_created timestamp rejects it before any write, mirroring
    # create_membership and provision_user (read informs the item, the
    # ConditionCheck enforces existence).
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        _provision_org(
            ddb,
            make_organization(organization_id="org_test_0002"),
            make_membership(
                membership_id="mem_test_0002",
                organization_id="org_ghost_0001",
                user_id="usr_test_0001",
            ),
            [make_audit_event(audit_id="aud_test_0002", organization_id="org_test_0002")],
        )
    ddb.assert_no_leak(excinfo.value)
    _assert_all_tables_empty(ddb)


def test_provision_organization_external_audit_org_enforced_by_condition_check(
    ddb: _DynamoDb,
) -> None:
    # An audit event referencing an organization outside the batch (and
    # unknown) fails the organizations ConditionCheck — the batch's own org
    # does not excuse a foreign reference (SQLite FK parity), and the whole
    # rejected batch leaves zero residue. The membership's user is created so
    # the foreign audit org is the only parent that can fail.
    ddb.storage.create_user(make_user())
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        _provision_org(
            ddb,
            make_organization(organization_id="org_test_0002"),
            make_membership(
                membership_id="mem_test_0002",
                organization_id="org_test_0002",
                user_id="usr_test_0001",
            ),
            [make_audit_event(audit_id="aud_test_0002", organization_id="org_ghost_0001")],
        )
    ddb.assert_no_leak(excinfo.value)
    # Zero residue from the batch: only the setup user (and its email
    # constraint) remains.
    assert ddb.tables.items("organizations") == []
    assert ddb.tables.items("memberships") == []
    assert ddb.tables.items("audit_events") == []
    assert len(ddb.tables.items("unique_constraints")) == 1


# ---------------------------------------------------------------------------
# Contract surface: with the task-7 compound in place the adapter carries all
# 19 protocol methods, so the runtime-checkable isinstance proof passes.
# ---------------------------------------------------------------------------


def test_adapter_satisfies_the_runtime_checkable_storage_protocol(ddb: _DynamoDb) -> None:
    members = get_protocol_members(Storage)
    assert len(members) == 19, members
    assert all(callable(getattr(DynamoDbStorage, name, None)) for name in members)
    # The same proof the SQLite adapter carries: a constructed adapter is an
    # instance of the protocol, not just a structural look-alike.
    assert isinstance(ddb.storage, Storage)
