"""DynamoDB Local proofs for the users + external-identity operations (task 3).

Marker-gated (``dynamodb_local``): every test here skips with an explicit reason
unless ``FEEDNOW_DYNAMODB_LOCAL_ENDPOINT`` is set and reachable, so the default
suite stays green without Docker (``docs/operations.md`` carries the run
command).

These are **direct adapter calls**, not the conformance suite (task 8 runs the
shared 60 cases unchanged): the point here is to pin the DynamoDB translation of
the 12 users/identity behaviors on the real transactional path — the
``TransactWriteItems`` atomicity, the positional conflict classification
(decision 3), the key-only constraint lookups (decision 2), and the tenant
normalization inside the constraint key (decision 6). Domain inputs come from the
suite's own deterministic builders so the fixtures match the conformance cases
exactly. Every failure path asserts the domain error *class*, the conflict *kind*,
an echo-free message, and — by scanning the tables directly — that the rejected
batch left no residue.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

import pytest
from storage_contract.suite import make_identity, make_user

from app.models.enums import IdentityProvider
from app.models.ids import UserId
from app.models.user import User
from app.storage.contract import (
    DuplicateEntityError,
    DuplicateEntityKind,
    EntityNotFoundError,
    ReferenceNotFoundError,
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


def _email_constraint_pk(email: str) -> str:
    return encode_constraint_key(ConstraintKind.USER_EMAIL, email)


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
    # Both items landed: the base record and the email constraint guard.
    assert [item["pk"] for item in ddb.tables.items("users")] == [str(user.id)]
    constraint = ddb.tables.item("unique_constraints", _email_constraint_pk(user.email))
    assert constraint is not None
    assert constraint["kind"] == ConstraintKind.USER_EMAIL.value
    assert constraint["entity_id"] == str(user.id)
    assert constraint["user_id"] == str(user.id)


def test_get_unknown_user_raises_entity_not_found(ddb: _DynamoDb) -> None:
    with pytest.raises(EntityNotFoundError) as excinfo:
        ddb.storage.get_user(UserId("usr_missing_0001"))
    ddb.assert_no_leak(excinfo.value)


def test_duplicate_email_raises_user_email_conflict(ddb: _DynamoDb) -> None:
    first = make_user()
    ddb.storage.create_user(first)
    # Email is a constraint, never an identity: a different ``usr_`` id with a
    # taken email is rejected as a domain conflict.
    duplicate = make_user(user_id="usr_test_0002", email=first.email)
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.create_user(duplicate)
    assert excinfo.value.kind is DuplicateEntityKind.USER_EMAIL
    ddb.assert_no_leak(excinfo.value)
    # The whole transaction rolled back: the winner is intact and the rejected
    # id was never consumed, so a clean insert of it succeeds.
    assert ddb.storage.get_user(first.id) == first
    ddb.storage.create_user(make_user(user_id="usr_test_0002"))
    assert len(ddb.tables.items("users")) == 2
    assert len(ddb.tables.items("unique_constraints")) == 2


def test_duplicate_user_id_raises_entity_id_conflict(ddb: _DynamoDb) -> None:
    first = make_user()
    ddb.storage.create_user(first)
    # Same ``usr_`` id, different email: the base put's condition fails first in
    # submission order, so this is a record-id conflict, not an email one.
    with pytest.raises(DuplicateEntityError) as excinfo:
        ddb.storage.create_user(make_user(email="other@example.test"))
    assert excinfo.value.kind is DuplicateEntityKind.ENTITY_ID
    ddb.assert_no_leak(excinfo.value)
    assert ddb.storage.get_user(first.id) == first
    # And the rejected email's constraint item was never written.
    assert ddb.tables.item("unique_constraints", _email_constraint_pk("other@example.test")) is None


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
