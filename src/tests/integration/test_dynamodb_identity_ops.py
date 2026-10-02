"""DynamoDB Local proofs for the users + external-identity operations (implementation).

Marker-gated (``dynamodb_local``): every test here skips with an explicit reason
unless ``FEEDNOW_DYNAMODB_LOCAL_ENDPOINT`` is set and reachable, so the default
suite stays green without Docker (``docs/operations.md`` carries the run
command).

These are **direct adapter calls**, not the conformance suite (implementation runs the
shared 73 cases unchanged): the point here is to pin the DynamoDB translation of
the 12 users/identity behaviors on the real transactional path — the
``TransactWriteItems`` atomicity, the positional conflict classification
(design choice 3), the key-only constraint lookups (design choice 2), the tenant
normalization inside the constraint key (design choice 6), and — from application-role — the
``application_role``/``g_email`` attributes on the stored item, the coexistence
of two users sharing an address, and the ``by-email`` ``list_users_by_email``
read. From admin the file also pins the ``g_role`` write and the
``transition_application_role`` DynamoDB replication — SQLite parity on every
implementation suite scenario plus a threaded concurrent double-revocation race
proving exactly one succeeds. Domain inputs come from the suite's own
deterministic builders so the
fixtures match the conformance cases
exactly. Every failure path asserts the domain error *class*, the conflict *kind*,
an echo-free message, and — by scanning the tables directly — that the rejected
batch left no residue.

Current behavior and invariants: ``docs/authentication.md``."""

from __future__ import annotations

import threading
from collections.abc import Iterator, Mapping
from typing import Any

import pytest
from storage_contract.suite import (
    T0,
    T1,
    T2,
    T4,
    make_audit_event,
    make_identity,
    make_organization,
    make_user,
)

from app.models.enums import ApplicationRole, IdentityProvider, UserStatus
from app.models.ids import UserId
from app.models.user import User
from app.storage.contract import (
    DuplicateEntityError,
    DuplicateEntityKind,
    EntityNotFoundError,
    LastActiveAdministratorError,
    ReferenceNotFoundError,
    RoleTransitionOutcome,
)
from app.storage.dynamodb import (
    SCHEMA,
    ConstraintKind,
    DynamoDbStorage,
    encode_constraint_key,
    encode_external_identity_value,
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

    def item(self, table: str, pk: str) -> dict[str, Any] | None:
        """One item by partition key, or ``None`` when absent."""
        response = self._resource.Table(f"{self.prefix}{table}").get_item(
            Key={"pk": pk}, ConsistentRead=True
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


def _identity_constraint_pk(
    provider: IdentityProvider, provider_subject: str, provider_tenant: str | None
) -> str:
    return encode_constraint_key(
        ConstraintKind.EXTERNAL_IDENTITY,
        encode_external_identity_value(provider, provider_subject, provider_tenant),
    )


# ---------------------------------------------------------------------------
# Users: create/round-trip, not-found, and the two conflict kinds
# ---------------------------------------------------------------------------


def test_create_user_returns_and_persists_the_domain_user(ddb: _DynamoDb) -> None:
    user = make_user()
    assert ddb.storage.create_user(user) == user
    assert ddb.storage.get_user(user.id) == user
    # Phase 12: the base record is the whole write — the email constraint guard
    # is gone, so no constraint item exists for a user creation at all.
    assert [item["pk"] for item in ddb.tables.items("users")] == [str(user.id)]
    assert ddb.tables.items("unique_constraints") == []
    stored = ddb.tables.item("users", str(user.id))
    assert stored is not None
    # The role is written (never left to a read-side default), the exact
    # address is duplicated onto the by-email GSI partition attribute, and
    # Phase 13 duplicates the role onto the by-application-role partition
    # attribute.
    assert stored["application_role"] == "user"
    assert stored["g_email"] == user.email
    assert stored["g_role"] == "user" == stored["application_role"]


def test_get_unknown_user_raises_entity_not_found(ddb: _DynamoDb) -> None:
    with pytest.raises(EntityNotFoundError) as excinfo:
        ddb.storage.get_user(UserId("usr_missing_0001"))
    ddb.assert_no_leak(excinfo.value)


def test_duplicate_email_creates_two_coexisting_users(ddb: _DynamoDb) -> None:
    first = make_user()
    ddb.storage.create_user(first)
    # Phase 12: email is a lookup field, not an identity or a constraint, so a
    # different ``usr_`` id carrying the same address is a legal write.
    duplicate = make_user(user_id="usr_test_0002", email=first.email)
    assert ddb.storage.create_user(duplicate) == duplicate
    assert ddb.storage.get_user(first.id) == first
    assert ddb.storage.get_user(duplicate.id) == duplicate
    assert len(ddb.tables.items("users")) == 2
    assert ddb.tables.items("unique_constraints") == []


def test_list_users_by_email_returns_zero_one_many_in_contract_order(
    ddb: _DynamoDb,
) -> None:
    # The by-email GSI read: an unknown address is an empty list (never
    # EntityNotFoundError), a unique address one user, a shared address every
    # carrier ordered by (created_at, id) — the index sorts by ``pk``, so the
    # contract ordering is the adapter's job.
    assert ddb.storage.list_users_by_email("nobody@example.test") == []
    later = make_user(user_id="usr_test_0002", email="shared@example.test", created_at=T1)
    earlier = make_user(user_id="usr_test_0001", email="shared@example.test", created_at=T0)
    unrelated = make_user(user_id="usr_test_0003", email="other@example.test", created_at=T0)
    # Insertion order is scrambled: the read, not the write sequence, orders.
    ddb.storage.create_user(unrelated)
    ddb.storage.create_user(later)
    ddb.storage.create_user(earlier)
    assert ddb.storage.list_users_by_email("shared@example.test") == [earlier, later]
    assert ddb.storage.list_users_by_email(unrelated.email) == [unrelated]


def test_duplicate_user_id_raises_entity_id_conflict(ddb: _DynamoDb) -> None:
    first = make_user()
    ddb.storage.create_user(first)
    # Same ``usr_`` id, different email: the base put's condition fails, so this
    # is a record-id conflict (the only one a user write can now raise).
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.create_user(make_user(email="other@example.test"))
    assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID
    ddb.assert_no_leak(excinfo.value)
    assert ddb.storage.get_user(first.id) == first
    # And the rejected write left no trace anywhere else in the schema.
    assert len(ddb.tables.items("users")) == 1
    assert ddb.tables.items("unique_constraints") == []


# ---------------------------------------------------------------------------
# External identities: create, tuple lookup (both tenant forms), conflicts, FK
# ---------------------------------------------------------------------------


def test_identity_create_and_lookup_with_explicit_tenant(ddb: _DynamoDb) -> None:
    user = make_user()
    ddb.storage.create_user(user)
    identity = make_identity(user_id=str(user.id), provider_tenant="shop-a.example.myshopify.com")
    assert ddb.storage.create_external_identity(identity) == identity
    resolved = ddb.storage.get_user_by_external_identity(
        provider=identity.provider,
        provider_subject=identity.provider_subject,
        provider_tenant="shop-a.example.myshopify.com",
    )
    assert resolved == user
    # A different tenant is a different tuple: the lookup must not match.
    with pytest.raises(EntityNotFoundError):
        ddb.storage.get_user_by_external_identity(
            provider=identity.provider,
            provider_subject=identity.provider_subject,
            provider_tenant="shop-b.example.myshopify.com",
        )


def test_identity_create_and_lookup_with_none_tenant(ddb: _DynamoDb) -> None:
    user = make_user()
    ddb.storage.create_user(user)
    identity = make_identity(user_id=str(user.id), provider_tenant=None)
    ddb.storage.create_external_identity(identity)
    # ``None`` and the omitted argument resolve the same tuple, and the stored
    # item carries the normalized empty tenant — never a NULL.
    assert (
        ddb.storage.get_user_by_external_identity(
            provider=identity.provider, provider_subject=identity.provider_subject
        )
        == user
    )
    assert (
        ddb.storage.get_user_by_external_identity(
            provider=identity.provider,
            provider_subject=identity.provider_subject,
            provider_tenant=None,
        )
        == user
    )
    stored = ddb.tables.item("external_identities", str(identity.id))
    assert stored is not None
    assert stored["provider_tenant"] == ""
    assert (
        ddb.tables.item(
            "unique_constraints",
            _identity_constraint_pk(identity.provider, identity.provider_subject, None),
        )
        is not None
    )


def test_unknown_identity_tuple_raises_entity_not_found(ddb: _DynamoDb) -> None:
    # A miss raises (never ``None``): this is Phase 03's provisioning signal.
    with pytest.raises(EntityNotFoundError) as excinfo:
        ddb.storage.get_user_by_external_identity(
            provider=IdentityProvider.COGNITO,
            provider_subject="subject-never-seen",
        )
    ddb.assert_no_leak(excinfo.value)


def test_duplicate_identity_with_explicit_tenant_is_rejected(ddb: _DynamoDb) -> None:
    owner = make_user()
    other = make_user(user_id="usr_test_0002")
    ddb.storage.create_user(owner)
    ddb.storage.create_user(other)
    tenant = "shop-a.example.myshopify.com"
    ddb.storage.create_external_identity(
        make_identity(user_id=str(owner.id), provider_tenant=tenant)
    )
    # Different record id *and* different user: the tuple constraint rejects it.
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.create_external_identity(
            make_identity(
                identity_id="extid_test_0002",
                user_id=str(other.id),
                provider_tenant=tenant,
            )
        )
    assert excinfo.value.kind is DuplicateEntityKind.EXTERNAL_IDENTITY
    ddb.assert_no_leak(excinfo.value)
    # Rolled back: the loser's record id is unconsumed, so it is reusable.
    assert ddb.tables.item("external_identities", "extid_test_0002") is None
    ddb.storage.create_external_identity(
        make_identity(
            identity_id="extid_test_0002",
            user_id=str(other.id),
            provider_subject="subject-cognito-0002",
        )
    )


def test_duplicate_identity_with_none_tenant_is_rejected(ddb: _DynamoDb) -> None:
    # The ``''`` normalization proof: with a NULL tenant the two tuples would be
    # distinct and a duplicate cognito identity would slip through.
    owner = make_user()
    other = make_user(user_id="usr_test_0002")
    ddb.storage.create_user(owner)
    ddb.storage.create_user(other)
    ddb.storage.create_external_identity(make_identity(user_id=str(owner.id)))
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.create_external_identity(
            make_identity(identity_id="extid_test_0002", user_id=str(other.id))
        )
    assert excinfo.value.kind is DuplicateEntityKind.EXTERNAL_IDENTITY
    ddb.assert_no_leak(excinfo.value)


def test_duplicate_identity_record_id_raises_entity_id_conflict(ddb: _DynamoDb) -> None:
    # A taken ``extid_`` record id with a *fresh* tuple is a record-id conflict,
    # not a tuple conflict (base put precedes constraint put in submission order).
    owner = make_user()
    ddb.storage.create_user(owner)
    ddb.storage.create_external_identity(make_identity(user_id=str(owner.id)))
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.create_external_identity(
            make_identity(user_id=str(owner.id), provider_subject="subject-cognito-0002")
        )
    assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID
    ddb.assert_no_leak(excinfo.value)
    # The fresh tuple's constraint item was never written by the rejected batch.
    assert (
        ddb.tables.item(
            "unique_constraints",
            _identity_constraint_pk(IdentityProvider.COGNITO, "subject-cognito-0002", None),
        )
        is None
    )


def test_identity_for_unknown_user_raises_reference_not_found(ddb: _DynamoDb) -> None:
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        ddb.storage.create_external_identity(make_identity(user_id="usr_ghost_0001"))
    ddb.assert_no_leak(excinfo.value)
    # DynamoDB has no foreign keys: the parent ConditionCheck must leave *both*
    # the base item and the constraint item unwritten.
    assert ddb.tables.items("external_identities") == []
    assert ddb.tables.items("unique_constraints") == []


# ---------------------------------------------------------------------------
# Boundary guarantees: domain types only, no identity coercion
# ---------------------------------------------------------------------------


def test_lookup_by_identity_returns_domain_user_without_row_leakage(ddb: _DynamoDb) -> None:
    user = make_user()
    ddb.storage.create_user(user)
    identity = make_identity(user_id=str(user.id), provider_tenant="shop-a.example.myshopify.com")
    ddb.storage.create_external_identity(identity)
    resolved = ddb.storage.get_user_by_external_identity(
        provider=identity.provider,
        provider_subject=identity.provider_subject,
        provider_tenant="shop-a.example.myshopify.com",
    )
    # The exact domain ``User`` (the model is ``extra="forbid"``, so equality
    # already proves no extra attributes crossed), never an item mapping.
    assert type(resolved) is User
    assert resolved == user
    assert not isinstance(resolved, Mapping)


def test_provider_subject_is_never_matched_as_a_user_id(ddb: _DynamoDb) -> None:
    # The subject *is* another user's id here: resolution goes through the
    # constraint item's ``user_id``, so a subject is never read as a ``usr_`` key.
    owner = make_user()
    stranger = make_user(user_id="usr_test_0002")
    ddb.storage.create_user(owner)
    ddb.storage.create_user(stranger)
    identity = make_identity(user_id=str(owner.id), provider_subject="usr_test_0002")
    ddb.storage.create_external_identity(identity)
    resolved = ddb.storage.get_user_by_external_identity(
        provider=identity.provider, provider_subject="usr_test_0002"
    )
    assert resolved == owner
    assert resolved != stranger


def test_identity_constraint_item_is_key_only_and_carries_the_owner(ddb: _DynamoDb) -> None:
    # Decision 2: the constraint table has no sort key, so the tuple lookup is a
    # single GetItem whose PK is fully built from the lookup's own inputs.
    user = make_user()
    ddb.storage.create_user(user)
    identity = make_identity(user_id=str(user.id), provider_tenant="shop-a.example.myshopify.com")
    ddb.storage.create_external_identity(identity)
    pk = _identity_constraint_pk(
        identity.provider, identity.provider_subject, "shop-a.example.myshopify.com"
    )
    assert pk == (
        f"external_identity#cognito#{identity.provider_subject}#shop-a.example.myshopify.com"
    )
    constraint = ddb.tables.item("unique_constraints", pk)
    assert constraint is not None
    assert set(constraint) == {"pk", "kind", "entity_id", "user_id"}
    assert constraint["user_id"] == str(user.id)
    assert constraint["entity_id"] == str(identity.id)


# ---------------------------------------------------------------------------
# Phase 13: transition_application_role — parity on every task-1 suite
# scenario (grant/revoke commit, the idempotent NO_CHANGE, the unknown-user
# signal, the last-ACTIVE-admin refusal, the DISABLED-admin guard bypass, the
# other-ACTIVE-admin allowance, and the audit-parent integrity), each also
# pinning the DynamoDB-specific mechanism: the g_role index key is rewritten
# in lockstep with application_role, and every refusal leaves zero residue.
# ---------------------------------------------------------------------------


def test_transition_grant_persists_role_index_key_and_audit(ddb: _DynamoDb) -> None:
    user = make_user()
    organization = make_organization()
    ddb.storage.create_user(user)
    ddb.storage.create_organization(organization)
    audit = make_audit_event(action="user.application_role.granted", created_at=T2)
    result = ddb.storage.transition_application_role(
        user_id=user.id,
        expected_role=ApplicationRole.USER,
        new_role=ApplicationRole.ADMIN,
        updated_at=T2,
        audit_event=audit,
    )
    assert result.outcome is RoleTransitionOutcome.TRANSITIONED
    assert result.user.id == user.id
    assert result.user.application_role is ApplicationRole.ADMIN
    assert result.user.updated_at == T2
    assert result.user.created_at == user.created_at
    assert ddb.storage.get_user(user.id) == result.user
    # The CAS rewrote the denormalized by-application-role key with the role.
    stored = ddb.tables.item("users", str(user.id))
    assert stored is not None
    assert stored["g_role"] == "admin" == stored["application_role"]
    # The audit event committed inside the same transaction (duplicate-append
    # proof: the aud_ id is taken).
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.append_audit_event(audit)
    assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID


def test_transition_revoke_persists_role_index_key_and_audit(ddb: _DynamoDb) -> None:
    first = make_user(user_id="usr_test_0001", application_role=ApplicationRole.ADMIN)
    second = make_user(user_id="usr_test_0002", application_role=ApplicationRole.ADMIN)
    organization = make_organization()
    ddb.storage.create_user(first)
    ddb.storage.create_user(second)
    ddb.storage.create_organization(organization)
    audit = make_audit_event(
        action="user.application_role.revoked",
        actor_user_id="usr_test_0001",
        created_at=T2,
    )
    result = ddb.storage.transition_application_role(
        user_id=first.id,
        expected_role=ApplicationRole.ADMIN,
        new_role=ApplicationRole.USER,
        updated_at=T2,
        audit_event=audit,
    )
    assert result.outcome is RoleTransitionOutcome.TRANSITIONED
    assert result.user.application_role is ApplicationRole.USER
    assert result.user.updated_at == T2
    assert ddb.storage.get_user(first.id) == result.user
    stored = ddb.tables.item("users", str(first.id))
    assert stored is not None
    assert stored["g_role"] == "user" == stored["application_role"]
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.append_audit_event(audit)
    assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID


def test_transition_repeat_calls_are_no_change_without_audit(ddb: _DynamoDb) -> None:
    user = make_user()
    organization = make_organization()
    ddb.storage.create_user(user)
    ddb.storage.create_organization(organization)
    first_audit = make_audit_event(action="user.application_role.granted", created_at=T2)
    granted = ddb.storage.transition_application_role(
        user_id=user.id,
        expected_role=ApplicationRole.USER,
        new_role=ApplicationRole.ADMIN,
        updated_at=T2,
        audit_event=first_audit,
    )
    assert granted.outcome is RoleTransitionOutcome.TRANSITIONED
    # Repeat grant on an ADMIN: NO_CHANGE with *zero* writes — no updated_at
    # movement, no index-key churn, and the second audit event is NOT
    # persisted (the caller must not re-append; the adapter already skipped).
    before = ddb.tables.item("users", str(user.id))
    repeat_audit = make_audit_event(
        audit_id="aud_test_0002",
        action="user.application_role.granted",
        created_at=T2,
    )
    repeated = ddb.storage.transition_application_role(
        user_id=user.id,
        expected_role=ApplicationRole.ADMIN,
        new_role=ApplicationRole.ADMIN,
        updated_at=T4,
        audit_event=repeat_audit,
    )
    assert repeated.outcome is RoleTransitionOutcome.NO_CHANGE
    assert repeated.user == granted.user
    assert repeated.user.updated_at == T2
    assert ddb.tables.item("users", str(user.id)) == before
    # The skipped aud_ id is still free: appending it proves NO_CHANGE wrote
    # no audit row (the duplicate-append proof, inverted).
    assert ddb.storage.append_audit_event(repeat_audit) is None
    # Revoke of a plain USER is likewise an idempotent NO_CHANGE.
    plain = make_user(user_id="usr_test_0002")
    ddb.storage.create_user(plain)
    revoke_audit = make_audit_event(
        audit_id="aud_test_0003",
        actor_user_id="usr_test_0002",
        action="user.application_role.revoked",
        created_at=T2,
    )
    revoked = ddb.storage.transition_application_role(
        user_id=plain.id,
        expected_role=ApplicationRole.USER,
        new_role=ApplicationRole.USER,
        updated_at=T2,
        audit_event=revoke_audit,
    )
    assert revoked.outcome is RoleTransitionOutcome.NO_CHANGE
    assert revoked.user == plain
    assert ddb.storage.append_audit_event(revoke_audit) is None


def test_transition_unknown_user_raises_entity_not_found(ddb: _DynamoDb) -> None:
    organization = make_organization()
    ddb.storage.create_organization(organization)
    audit = make_audit_event(action="user.application_role.granted")
    with pytest.raises(EntityNotFoundError) as excinfo:
        ddb.storage.transition_application_role(
            user_id=UserId("usr_missing_0001"),
            expected_role=ApplicationRole.USER,
            new_role=ApplicationRole.ADMIN,
            updated_at=T2,
            audit_event=audit,
        )
    ddb.assert_no_leak(excinfo.value)
    # The refused call submitted nothing: no audit row exists and the audit
    # id is still unused (the duplicate-append proof, inverted).
    assert ddb.tables.items("audit_events") == []
    assert ddb.storage.append_audit_event(audit) is None


def test_transition_refuses_demoting_the_last_active_administrator(ddb: _DynamoDb) -> None:
    admin = make_user(application_role=ApplicationRole.ADMIN)
    organization = make_organization()
    ddb.storage.create_user(admin)
    ddb.storage.create_organization(organization)
    audit = make_audit_event(action="user.application_role.revoked")
    with pytest.raises(LastActiveAdministratorError) as excinfo:
        ddb.storage.transition_application_role(
            user_id=admin.id,
            expected_role=ApplicationRole.ADMIN,
            new_role=ApplicationRole.USER,
            updated_at=T2,
            audit_event=audit,
        )
    ddb.assert_no_leak(excinfo.value)
    # Full rollback (no transaction was ever submitted): the target keeps
    # ADMIN — role attribute and index key alike — and the refused event's
    # aud_ id still appends cleanly.
    assert ddb.storage.get_user(admin.id) == admin
    stored = ddb.tables.item("users", str(admin.id))
    assert stored is not None
    assert stored["g_role"] == "admin"
    assert ddb.tables.items("audit_events") == []
    assert ddb.storage.append_audit_event(audit) is None


def test_transition_refuses_demotion_when_only_other_admin_is_disabled(
    ddb: _DynamoDb,
) -> None:
    # The guard counts *ACTIVE* admins only: the status filter on the
    # by-application-role Query hides the DISABLED co-admin, so demoting the
    # last ACTIVE admin still refuses (spec 13 required behavior 3).
    active_admin = make_user(user_id="usr_test_0001", application_role=ApplicationRole.ADMIN)
    dormant_admin = make_user(
        user_id="usr_test_0002",
        status=UserStatus.DISABLED,
        application_role=ApplicationRole.ADMIN,
    )
    organization = make_organization()
    ddb.storage.create_user(active_admin)
    ddb.storage.create_user(dormant_admin)
    ddb.storage.create_organization(organization)
    audit = make_audit_event(
        actor_user_id="usr_test_0001",
        action="user.application_role.revoked",
    )
    with pytest.raises(LastActiveAdministratorError):
        ddb.storage.transition_application_role(
            user_id=active_admin.id,
            expected_role=ApplicationRole.ADMIN,
            new_role=ApplicationRole.USER,
            updated_at=T2,
            audit_event=audit,
        )
    assert ddb.storage.get_user(active_admin.id) == active_admin
    assert ddb.tables.items("audit_events") == []
    assert ddb.storage.append_audit_event(audit) is None


def test_transition_demotion_allowed_while_another_active_admin_exists(
    ddb: _DynamoDb,
) -> None:
    # The deterministic witness (earliest (created_at, id) other ACTIVE admin)
    # is checked but never written: its record stays byte-identical.
    first = make_user(user_id="usr_test_0001", application_role=ApplicationRole.ADMIN)
    second = make_user(
        user_id="usr_test_0002",
        application_role=ApplicationRole.ADMIN,
        created_at=T1,
    )
    organization = make_organization()
    ddb.storage.create_user(first)
    ddb.storage.create_user(second)
    ddb.storage.create_organization(organization)
    audit = make_audit_event(
        actor_user_id="usr_test_0001",
        action="user.application_role.revoked",
    )
    result = ddb.storage.transition_application_role(
        user_id=first.id,
        expected_role=ApplicationRole.ADMIN,
        new_role=ApplicationRole.USER,
        updated_at=T2,
        audit_event=audit,
    )
    assert result.outcome is RoleTransitionOutcome.TRANSITIONED
    assert result.user.application_role is ApplicationRole.USER
    assert ddb.storage.get_user(second.id) == second
    witness_before = ddb.tables.item("users", str(second.id))
    assert witness_before is not None
    assert witness_before["g_role"] == "admin"


def test_transition_disabled_admin_demotion_skips_the_active_guard(ddb: _DynamoDb) -> None:
    # A DISABLED admin is the sole admin: demoting it cannot change the
    # ACTIVE-admin count, so the guard (and its Query) is skipped entirely.
    admin = make_user(
        status=UserStatus.DISABLED,
        application_role=ApplicationRole.ADMIN,
    )
    organization = make_organization()
    ddb.storage.create_user(admin)
    ddb.storage.create_organization(organization)
    audit = make_audit_event(action="user.application_role.revoked")
    result = ddb.storage.transition_application_role(
        user_id=admin.id,
        expected_role=ApplicationRole.ADMIN,
        new_role=ApplicationRole.USER,
        updated_at=T2,
        audit_event=audit,
    )
    assert result.outcome is RoleTransitionOutcome.TRANSITIONED
    assert result.user.application_role is ApplicationRole.USER
    assert result.user.status is UserStatus.DISABLED
    assert ddb.storage.get_user(admin.id) == result.user


def test_transition_with_unknown_audit_organization_raises_reference_not_found(
    ddb: _DynamoDb,
) -> None:
    # Audit-parent integrity (contract-pinned): the organizations-parent
    # ConditionCheck inside the same transaction refuses a missing anchor and
    # the *role write* rolls back with it.
    user = make_user()
    ddb.storage.create_user(user)
    audit = make_audit_event(
        organization_id="org_ghost_0001",
        action="user.application_role.granted",
    )
    with pytest.raises(ReferenceNotFoundError) as excinfo:
        ddb.storage.transition_application_role(
            user_id=user.id,
            expected_role=ApplicationRole.USER,
            new_role=ApplicationRole.ADMIN,
            updated_at=T2,
            audit_event=audit,
        )
    ddb.assert_no_leak(excinfo.value)
    # Full rollback: no role write, no index-key churn, and no audit row (the
    # ghost-organization event can never append on this table either).
    assert ddb.storage.get_user(user.id) == user
    stored = ddb.tables.item("users", str(user.id))
    assert stored is not None
    assert stored["g_role"] == "user"
    assert ddb.tables.items("audit_events") == []


def test_concurrent_double_revocation_of_the_last_pair_lets_exactly_one_win(
    ddb: _DynamoDb,
) -> None:
    # The DynamoDB analogue of SQLite's BEGIN IMMEDIATE serialization: two
    # threads demote the only two ACTIVE admins at once. Each guard read sees
    # the other as witness; commit-time condition evaluation (witness
    # ConditionCheck + target CAS) serializes the transactions so exactly one
    # commits and the other is refused with LastActiveAdministratorError —
    # never two, never zero, and never a partial write.
    first = make_user(user_id="usr_test_0001", application_role=ApplicationRole.ADMIN)
    second = make_user(
        user_id="usr_test_0002",
        application_role=ApplicationRole.ADMIN,
        created_at=T1,
    )
    organization = make_organization()
    ddb.storage.create_user(first)
    ddb.storage.create_user(second)
    ddb.storage.create_organization(organization)
    endpoint = local.require_local_endpoint()
    challenger = local.make_dynamodb_storage(
        ddb.tables.prefix, resource=local.make_dynamodb_resource(endpoint)
    )
    barrier = threading.Barrier(2, timeout=30)
    outcomes: dict[str, object] = {}

    def revoke(target_id: str, audit_id: str, storage: DynamoDbStorage) -> None:
        audit = make_audit_event(
            audit_id=audit_id,
            actor_user_id=target_id,
            action="user.application_role.revoked",
            created_at=T2,
        )
        barrier.wait()
        try:
            result = storage.transition_application_role(
                user_id=UserId(target_id),
                expected_role=ApplicationRole.ADMIN,
                new_role=ApplicationRole.USER,
                updated_at=T2,
                audit_event=audit,
            )
            outcomes[target_id] = result.outcome
        except LastActiveAdministratorError:
            outcomes[target_id] = "refused"

    threads = [
        threading.Thread(target=revoke, args=("usr_test_0001", "aud_race_0001", ddb.storage)),
        threading.Thread(target=revoke, args=("usr_test_0002", "aud_race_0002", challenger)),
    ]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        assert not any(thread.is_alive() for thread in threads), "revocation deadlocked"
        # Both threads reached a terminal outcome; exactly one transitioned.
        assert len(outcomes) == 2
        assert list(outcomes.values()).count(RoleTransitionOutcome.TRANSITIONED) == 1
        assert list(outcomes.values()).count("refused") == 1
        # Exactly one ACTIVE admin remains, and the loser's audit row never
        # existed (its aud_ id is still free while the winner's is taken).
        admins = [
            user
            for user in (ddb.storage.get_user(first.id), ddb.storage.get_user(second.id))
            if user.application_role is ApplicationRole.ADMIN
        ]
        assert len(admins) == 1
        loser_id = next(target for target, outcome in outcomes.items() if outcome == "refused")
        winner_id = next(target for target in outcomes if target != loser_id)
        with pytest.raises(DuplicateEntityError):
            ddb.storage.append_audit_event(
                make_audit_event(
                    audit_id=f"aud_race_{winner_id[-4:]}",
                    actor_user_id=winner_id,
                    action="user.application_role.revoked",
                    created_at=T2,
                )
            )
        assert (
            ddb.storage.append_audit_event(
                make_audit_event(
                    audit_id=f"aud_race_{loser_id[-4:]}",
                    actor_user_id=loser_id,
                    action="user.application_role.revoked",
                    created_at=T2,
                )
            )
            is None
        )
    finally:
        challenger.close()
