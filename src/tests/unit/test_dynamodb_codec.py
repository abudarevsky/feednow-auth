"""Unit proofs for the DynamoDB adapter skeleton (Phase 06 task 2).

No Docker, no network: the codecs, key builders, cursor round-trip, and the
factory's injected-resource seam are pure/off-line, so every assertion here
runs against synthetic inputs. Error-translation proofs live in
``test_dynamodb_errors.py``; contract *behavior* (duplicates, CAS, pagination,
provisioning) is owned by the DynamoDB Local ops tests (tasks 3-8) and the
conformance suite.

Verify lines covered:

- Timestamp codec round-trips, including the zero-microsecond sortable
  tripwire (a ``.000000`` value must stay fixed-width or a mixed GSI sort-key
  range mis-sorts).
- Tenant ``None`` <-> ``""`` normalization is lossless.
- Sort-key builders put the ``#``-separated id tiebreaker last.
- Cursor garbage/tampered/foreign-scope -> ``InvalidCursorError`` with fixed
  messages and no echo of the cursor content.
- The factory with an injected fake resource constructs without any network
  call, and ``close()`` shuts the client down / blocks reuse.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta, timezone

import pytest

import app.storage.contract as contract
from app.models.enums import IdentityProvider
from app.storage.dynamodb import (
    CURSOR_SCOPE_API_KEYS,
    CURSOR_SCOPE_MEMBERSHIPS,
    DUPLICATE_KIND_BY_CONSTRAINT,
    SCHEMA,
    ConstraintKind,
    DynamoDbStorage,
    decode_cursor,
    decode_provider_tenant,
    decode_timestamp,
    encode_constraint_key,
    encode_cursor,
    encode_external_identity_value,
    encode_provider_tenant,
    encode_sort_key,
    encode_timestamp,
    open_dynamodb_storage,
)

# ---------------------------------------------------------------------------
# Deterministic fixtures (fixed timestamps for the sortable-order proofs).
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 9, 12, 10, 0, 0, tzinfo=UTC)  # zero microseconds
_T1 = datetime(2026, 9, 12, 10, 0, 0, 123456, tzinfo=UTC)
_T2 = datetime(2026, 9, 12, 10, 0, 0, 1, tzinfo=UTC)  # one microsecond
_T3 = datetime(2026, 9, 12, 10, 0, 1, 0, tzinfo=UTC)  # one second later, zero µs


# -- timestamp codec ----------------------------------------------------------


def test_timestamp_round_trip_preserves_microseconds() -> None:
    for value in (_T0, _T1, _T2, _T3, datetime(2026, 1, 2, 3, 4, 5, 999999, tzinfo=UTC)):
        encoded = encode_timestamp(value)
        assert encoded.endswith("Z")
        assert decode_timestamp(encoded) == value


def test_zero_microsecond_values_stay_fixed_width() -> None:
    # The T3-vs-T2 tripwire: a zero-microsecond instant must render the full
    # ".000000" so it stays fixed-width and sorts AFTER a same-second value
    # that carries microseconds.
    assert encode_timestamp(_T0) == "2026-09-12T10:00:00.000000Z"
    assert len(encode_timestamp(_T0)) == len(encode_timestamp(_T2)) == 27


def test_mixed_sample_sorts_chronologically_and_lexicographically_alike() -> None:
    sample = [_T3, _T1, _T0, _T2, datetime(2025, 12, 31, 23, 59, 59, 500000, tzinfo=UTC)]
    encoded = [encode_timestamp(value) for value in sample]
    assert len(set(map(len, encoded))) == 1
    assert [decode_timestamp(text) for text in sorted(encoded)] == sorted(sample)


def test_non_utc_offsets_are_normalized_to_utc_on_encode() -> None:
    plus_two = datetime(2026, 9, 12, 12, 0, 0, tzinfo=timezone(timedelta(hours=2)))
    assert encode_timestamp(plus_two) == "2026-09-12T10:00:00.000000Z"


def test_decode_rejects_naive_and_malformed_stored_text() -> None:
    with pytest.raises(ValueError, match="naive"):
        decode_timestamp("2026-09-12T10:00:00")
    with pytest.raises(ValueError):
        decode_timestamp("not-a-timestamp")


# -- tenant codec -------------------------------------------------------------


def test_tenant_normalization_round_trip_is_lossless() -> None:
    assert encode_provider_tenant(None) == ""
    assert decode_provider_tenant("") is None
    for tenant in ("shop.example.myshopify.com", "a"):
        assert decode_provider_tenant(encode_provider_tenant(tenant)) == tenant


# -- constraint / sort-key builders ------------------------------------------


def test_constraint_key_puts_kind_first_hash_separator() -> None:
    key = encode_constraint_key(ConstraintKind.USER_EMAIL, "test@example.com")
    assert key == "user_email#test@example.com"


def test_membership_id_guard_maps_to_entity_id_kind() -> None:
    # Decision 2: the ``mem_`` record-id guard surfaces as ``entity_id``; the
    # ``membership`` kind belongs to the native org/user pair, not a constraint.
    assert DUPLICATE_KIND_BY_CONSTRAINT[ConstraintKind.MEMBERSHIP_ID] is (
        contract.DuplicateEntityKind.ENTITY_ID
    )
    assert DUPLICATE_KIND_BY_CONSTRAINT[ConstraintKind.API_KEY_ID] is (
        contract.DuplicateEntityKind.API_KEY_ID
    )
    assert DUPLICATE_KIND_BY_CONSTRAINT[ConstraintKind.EXTERNAL_IDENTITY] is (
        contract.DuplicateEntityKind.EXTERNAL_IDENTITY
    )


def test_external_identity_value_normalizes_tenant_into_the_key() -> None:
    with_tenant = encode_external_identity_value(
        IdentityProvider.SHOPIFY, "shop-1", "a.myshopify.com"
    )
    without = encode_external_identity_value(IdentityProvider.COGNITO, "sub-1", None)
    assert with_tenant == "shopify#shop-1#a.myshopify.com"
    # None and "" collapse to the same normalized tail (lossless via min_length).
    assert without == "cognito#sub-1#"
    assert encode_external_identity_value(IdentityProvider.COGNITO, "sub-1", "") == without


def test_sort_key_puts_id_tiebreaker_last() -> None:
    key = encode_sort_key(_T1, "mem_test_0001")
    assert key == "2026-09-12T10:00:00.123456Z#mem_test_0001"
    # Same instant, different id -> id orders them (tiebreaker is exact).
    assert encode_sort_key(_T1, "mem_a") < encode_sort_key(_T1, "mem_b")
    # Different instant orders first regardless of id.
    assert encode_sort_key(_T0, "mem_z") < encode_sort_key(_T1, "mem_a")


# -- keyset cursors -----------------------------------------------------------


def test_cursor_round_trip_returns_the_resume_key() -> None:
    resume = {"g_org": "org_test_0001", "g_created": encode_sort_key(_T1, "mem_test_0001")}
    cursor = encode_cursor(CURSOR_SCOPE_MEMBERSHIPS, resume)
    assert isinstance(cursor, str) and cursor
    assert decode_cursor(CURSOR_SCOPE_MEMBERSHIPS, cursor) == resume


def test_cursor_is_opaque_text_without_readable_position() -> None:
    cursor = encode_cursor(CURSOR_SCOPE_API_KEYS, {"g_org": "org_secret_01", "g_created": "x"})
    assert "org_secret_01" not in cursor
    assert "g_org" not in cursor


def test_foreign_scope_cursor_is_rejected() -> None:
    memberships_cursor = encode_cursor(CURSOR_SCOPE_MEMBERSHIPS, {"g_user": "usr_1"})
    with pytest.raises(contract.InvalidCursorError, match="different list"):
        decode_cursor(CURSOR_SCOPE_API_KEYS, memberships_cursor)


@pytest.mark.parametrize(
    "tampered",
    [
        "",
        "!!!not-base64!!!",
        "zzzz",
        "c2NvcGVk",  # valid base64 of "scoped": decodes, but is not JSON
        "\u00e9\u00fc",  # non-ascii: cannot even be encoded to the ascii base64 alphabet
    ],
)
def test_malformed_or_tampered_cursors_raise_invalid_cursor(tampered: str) -> None:
    with pytest.raises(contract.InvalidCursorError):
        decode_cursor(CURSOR_SCOPE_MEMBERSHIPS, tampered)


@pytest.mark.parametrize(
    "payload",
    [
        "[1,2]",  # not an object
        '{"scope":"memberships"}',  # missing resume
        '{"scope":"memberships","resume":{}}',  # empty resume
        '{"scope":"memberships","resume":{"g_user":5}}',  # non-string value
        '{"scope":"memberships","resume":{"g_user":"u"},"extra":1}',  # unknown key
        '{"scope":1,"resume":{"g_user":"u"}}',  # non-string scope
    ],
)
def test_malformed_cursor_payloads_raise_invalid_cursor(payload: str) -> None:
    encoded = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    with pytest.raises(contract.InvalidCursorError, match="malformed"):
        decode_cursor(CURSOR_SCOPE_MEMBERSHIPS, encoded)


def test_invalid_cursor_messages_never_echo_the_cursor() -> None:
    foreign = encode_cursor(CURSOR_SCOPE_API_KEYS, {"g_user": "usr_leakme"})
    for bad in (foreign, "!!!", "{}"):
        with pytest.raises(contract.InvalidCursorError) as excinfo:
            decode_cursor(CURSOR_SCOPE_MEMBERSHIPS, bad)
        message = str(excinfo.value)
        assert "usr_leakme" not in message
        assert bad[:6] not in message


# -- schema (single source) ---------------------------------------------------


def test_schema_is_the_seven_table_single_source() -> None:
    assert [spec.name for spec in SCHEMA] == [
        "users",
        "organizations",
        "external_identities",
        "audit_events",
        "api_keys",
        "memberships",
        "unique_constraints",
    ]
    # The harness re-exports the very same tuple object (no drift).
    from tests.support import dynamodb_local as local

    assert local.TABLE_SPECS is SCHEMA


# -- factory + adapter shell (injected fake, no network) ----------------------


class _FakeClient:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeTable:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeMeta:
    def __init__(self, client: _FakeClient) -> None:
        self.client = client


class _FakeResource:
    """Records Table() requests; never contacts a network."""

    def __init__(self) -> None:
        self.requested: list[str] = []
        self.meta = _FakeMeta(_FakeClient())

    def Table(self, name: str) -> _FakeTable:
        self.requested.append(name)
        return _FakeTable(name)


def test_factory_with_injected_resource_makes_no_network_call() -> None:
    resource = _FakeResource()
    storage = open_dynamodb_storage(table_prefix="pfx-", dynamodb_resource=resource)
    assert isinstance(storage, DynamoDbStorage)
    assert storage.table_prefix == "pfx-"
    assert resource.requested == []  # construction is inert


def test_table_accessor_applies_prefix() -> None:
    resource = _FakeResource()
    storage = open_dynamodb_storage(table_prefix="pfx-", dynamodb_resource=resource)
    table = storage._table("users")
    assert table.name == "pfx-users"
    assert resource.requested == ["pfx-users"]


def test_close_shuts_client_and_blocks_reuse() -> None:
    resource = _FakeResource()
    storage = open_dynamodb_storage(dynamodb_resource=resource)
    storage.close()
    assert resource.meta.client.closed is True
    with pytest.raises(contract.StorageError):
        storage._table("users")
    storage.close()  # idempotent: second close is a no-op, not an error


def test_resource_defaults_to_empty_prefix_when_omitted() -> None:
    storage = open_dynamodb_storage(dynamodb_resource=_FakeResource())
    assert storage.table_prefix == ""
