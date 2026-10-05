"""Unit proofs for the DynamoDB adapter skeleton (DynamoDB).

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
- The application-role users item carries ``application_role``/``g_email``, an absent
  role (pre-capability-12 item) reads back as ``user``, and a present-but-invalid
  role fails validation; no constraint kind or mapping names email any more.
- The admin users item additionally carries ``g_role`` (the
  ``by-application-role`` GSI partition attribute, always the exact
  ``application_role`` value), and the users ``TableSpec`` declares both GSIs.
- Cursor garbage/tampered/foreign-scope -> ``InvalidCursorError`` with fixed
  messages and no echo of the cursor content.
- The factory with an injected fake resource constructs without any network
  call, and ``close()`` shuts the client down / blocks reuse.

Current behavior and invariants: ``docs/architecture.md``."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

import app.storage.contract as contract
from app.models.enums import ApplicationRole, IdentityProvider, UserStatus
from app.models.ids import UserId
from app.models.service_authorization import ServiceAuthorizationCode
from app.models.session import AppSession, OAuthLoginState
from app.models.user import User
from app.storage.dynamodb import (
    CURSOR_SCOPE_API_KEYS,
    CURSOR_SCOPE_MEMBERSHIPS,
    DUPLICATE_KIND_BY_CONSTRAINT,
    SCHEMA,
    ConstraintKind,
    DynamoDbStorage,
    app_session_from_item,
    app_session_item,
    decode_cursor,
    decode_provider_tenant,
    decode_timestamp,
    encode_constraint_key,
    encode_cursor,
    encode_external_identity_value,
    encode_provider_tenant,
    encode_sort_key,
    encode_timestamp,
    oauth_login_state_from_item,
    oauth_login_state_item,
    open_dynamodb_storage,
    service_authorization_code_from_item,
    service_authorization_code_item,
    ttl_epoch_seconds,
    user_from_item,
    user_item,
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
    key = encode_constraint_key(ConstraintKind.ORGANIZATION_SLUG, "acme")
    assert key == "organization_slug#acme"


def test_no_constraint_kind_or_mapping_names_email() -> None:
    # Phase 12: email is a lookup field, not a uniqueness constraint, so the
    # adapter has no ``user_email`` guard item at all — the kind is gone from
    # the enum and from the constraint->conflict mapping (the frozen
    # ``DuplicateEntityKind.USER_EMAIL`` stays in the contract vocabulary but
    # is never translated on this adapter).
    assert "USER_EMAIL" not in {member.name for member in ConstraintKind}
    assert "user_email" not in {str(kind) for kind in ConstraintKind}
    assert DUPLICATE_KIND_BY_CONSTRAINT.keys() == set(ConstraintKind)
    assert contract.DuplicateEntityKind.USER_EMAIL not in DUPLICATE_KIND_BY_CONSTRAINT.values()
    # And the users table declares an index, not a constraint, for email.
    users_spec = next(spec for spec in SCHEMA if spec.name == "users")
    assert ("by-email", "g_email", "pk") in [
        (index.name, index.partition_key, index.sort_key) for index in users_spec.indexes
    ]


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


# -- users item codec (Phase 12: application role + email lookup key) ---------


def _user(**overrides: object) -> User:
    payload: dict[str, object] = {
        "id": UserId("usr_test_0001"),
        "display_name": "Test user",
        "email": "test@example.test",
        "status": UserStatus.ACTIVE,
        "created_at": _T1,
        "updated_at": _T1,
    }
    payload.update(overrides)
    return User.model_validate(payload)


def test_user_item_round_trips_role_and_email_lookup_key() -> None:
    admin = _user(application_role=ApplicationRole.ADMIN)
    item = user_item(admin)
    # The role is written as its enum string on every path (the writer always
    # names it), and g_email is the by-email GSI partition key: the exact
    # stored address, unnormalized, matching the SQLite index predicate.
    assert item["application_role"] == "admin"
    assert item["g_email"] == admin.email == item["email"]
    assert item["pk"] == "usr_test_0001"
    assert user_from_item(item) == admin


def test_user_item_writes_g_role_as_the_application_role_value() -> None:
    # Phase 13: g_role is the by-application-role GSI partition attribute and
    # carries exactly the application_role value on every write path — the
    # transition's conditional update rewrites both attributes from one value,
    # so the index can never lag the attribute it mirrors.
    admin_item = user_item(_user(application_role=ApplicationRole.ADMIN))
    assert admin_item["g_role"] == "admin" == admin_item["application_role"]
    user_item_mapping = user_item(_user(application_role=ApplicationRole.USER))
    assert user_item_mapping["g_role"] == "user" == user_item_mapping["application_role"]


def test_user_from_item_ignores_the_g_role_index_attribute() -> None:
    # g_role is index plumbing, never domain state: reconstruction reads the
    # application_role attribute, and the extra key does not leak (the model
    # is extra="forbid", so equality proves it).
    admin = _user(application_role=ApplicationRole.ADMIN)
    assert user_from_item(user_item(admin)) == admin
    drifted = user_item(admin)
    drifted["g_role"] = "user"  # a hypothetical lagging index copy
    assert user_from_item(drifted) == admin  # the attribute is not consulted


def test_user_item_writes_the_default_role_rather_than_omitting_it() -> None:
    item = user_item(_user())
    # Absence is reserved for pre-Phase-12 items; a fresh write always carries
    # the attribute, so the old-data read rule below cannot mask a bug here.
    assert item["application_role"] == "user"
    assert user_from_item(item).application_role is ApplicationRole.USER


def test_pre_phase_12_item_without_role_reads_back_as_user() -> None:
    legacy = user_item(_user(application_role=ApplicationRole.ADMIN))
    del legacy["application_role"]
    # Documented old-data rule: an absent attribute is a pre-Phase-12 row and
    # reads as the only role writers of that era could produce.
    assert user_from_item(legacy).application_role is ApplicationRole.USER


def test_present_but_invalid_stored_role_fails_validation() -> None:
    corrupt = user_item(_user())
    corrupt["application_role"] = "superuser"
    # The corrupt-value tripwire survives the old-data rule: only *absence*
    # defaults, a present-but-invalid value fails loudly.
    with pytest.raises(ValidationError):
        user_from_item(corrupt)


# -- schema (single source) ---------------------------------------------------


def test_schema_is_the_ten_table_single_source() -> None:
    assert [spec.name for spec in SCHEMA] == [
        "users",
        "organizations",
        "external_identities",
        "audit_events",
        "api_keys",
        "memberships",
        "unique_constraints",
        "oauth_login_states",
        "app_sessions",
        "service_authorization_codes",
    ]
    # The harness re-exports the very same tuple object (no drift).
    from tests.support import dynamodb_local as local

    assert local.TABLE_SPECS is SCHEMA


def test_phase_11_session_tables_are_pk_keyed_single_tables() -> None:
    # Phase 11 task 7: the two additive session stores are single-table,
    # partition-keyed by the caller-minted opaque id, with no GSI and no sort
    # key (the atomic get-and-delete and point read are both pk-only).
    by_name = {spec.name: spec for spec in SCHEMA}
    for name in ("oauth_login_states", "app_sessions"):
        spec = by_name[name]
        assert (spec.partition_key, spec.sort_key) == ("pk", None), name
        assert spec.indexes == (), name


def test_users_table_declares_the_phase_13_by_application_role_gsi() -> None:
    # Phase 13 task 6: the active-admin guard needs a real access path, so the
    # users table carries the by-application-role GSI (g_role partition, pk
    # sort) alongside by-email — additive index, base keys untouched.
    users_spec = next(spec for spec in SCHEMA if spec.name == "users")
    assert [(i.name, i.partition_key, i.sort_key) for i in users_spec.indexes] == [
        ("by-email", "g_email", "pk"),
        ("by-application-role", "g_role", "pk"),
    ]
    assert users_spec.partition_key == "pk"
    assert users_spec.sort_key is None
    # create_parameters keeps both GSI key attributes in the definitions.
    payload = users_spec.create_parameters("pfx-")
    defined = {d["AttributeName"] for d in payload["AttributeDefinitions"]}
    assert {"pk", "g_email", "g_role"} == defined
    names = [i["IndexName"] for i in payload["GlobalSecondaryIndexes"]]
    assert names == ["by-email", "by-application-role"]


# -- session item codecs (Phase 11 task 7) ------------------------------------


_LIVE = datetime(2100, 1, 1, 0, 0, 0, 123456, tzinfo=UTC)


def _login_state() -> OAuthLoginState:
    return OAuthLoginState(
        state_id="state_test_0000001",
        code_verifier="verifier-" + "0" * 34,
        return_url="/dashboard",
        expires_at=_LIVE,
    )


def _app_session() -> AppSession:
    return AppSession(
        session_id="sess_test_0000001",
        user_id=UserId("usr_test_0001"),
        expires_at=_LIVE,
    )


def test_ttl_epoch_seconds_is_whole_second_utc_epoch_int() -> None:
    epoch = ttl_epoch_seconds(_LIVE)
    assert isinstance(epoch, int)
    assert epoch == int(_LIVE.timestamp())


def test_oauth_login_state_item_round_trips_with_ttl_attribute() -> None:
    state = _login_state()
    item = oauth_login_state_item(state)
    assert item["pk"] == state.state_id
    # The exact microsecond instant lives in the sortable TEXT attribute; the
    # numeric epoch attribute is the (second-granularity) TTL pointer.
    assert item["expires_at"] == encode_timestamp(_LIVE)
    assert item["expires_at_epoch"] == ttl_epoch_seconds(_LIVE)
    assert oauth_login_state_from_item(item) == state


def test_app_session_item_round_trips_with_ttl_attribute() -> None:
    session = _app_session()
    item = app_session_item(session)
    assert item["pk"] == session.session_id
    assert item["user_id"] == "usr_test_0001"
    assert item["expires_at"] == encode_timestamp(_LIVE)
    assert item["expires_at_epoch"] == ttl_epoch_seconds(_LIVE)
    assert app_session_from_item(item) == session


def test_service_authorization_code_item_round_trips_without_plaintext() -> None:
    code = ServiceAuthorizationCode(
        code_digest="a" * 64,
        service_id="vispector",
        user_id="usr_test_0001",
        organization_id="org_test_0001",
        permissions=("projects:read", "inspect"),
        permission_version="membership-v1",
        expires_at=_LIVE,
    )
    item = service_authorization_code_item(code)
    assert item["pk"] == code.code_digest
    assert item["expires_at_epoch"] == ttl_epoch_seconds(_LIVE)
    assert "raw_code" not in item
    assert service_authorization_code_from_item(item) == code


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
