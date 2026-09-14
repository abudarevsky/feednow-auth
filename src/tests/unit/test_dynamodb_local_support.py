"""Unit proofs for the DynamoDB Local harness (no Docker, no network I/O).

Covers the harness contract from Phase 06 decision 8: env-var gating with
explicit skip reasons, a connect-level endpoint probe, the seven-table
names/key-schema spec (decision 2's layout), prefix hygiene, and the
create/delete lifecycle driven against an injected fake resource so no live
calls are made.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest
from botocore.exceptions import ClientError

from tests.support import dynamodb_local as local


@pytest.fixture(autouse=True)
def _clean_endpoint_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The gating tests own the env var; never inherit a developer's value."""
    monkeypatch.delenv(local.ENDPOINT_ENV_VAR, raising=False)


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "synthetic"}}, "DeleteTable")


class _FakeWaiter:
    def __init__(self, name: str, calls: list[tuple[str, str, dict[str, Any]]]) -> None:
        self._name = name
        self._calls = calls

    def wait(self, *, TableName: str, WaiterConfig: dict[str, Any]) -> None:
        self._calls.append((self._name, TableName, WaiterConfig))


class _FakeClient:
    def __init__(self, delete_errors: dict[str, Exception] | None = None) -> None:
        self.created_payloads: list[dict[str, Any]] = []
        self.deleted_names: list[str] = []
        self.waiter_calls: list[tuple[str, str, dict[str, Any]]] = []
        self._delete_errors = delete_errors or {}

    def create_table(self, **kwargs: Any) -> None:
        self.created_payloads.append(kwargs)

    def delete_table(self, *, TableName: str) -> None:
        error = self._delete_errors.get(TableName)
        if error is not None:
            raise error
        self.deleted_names.append(TableName)

    def get_waiter(self, name: str) -> _FakeWaiter:
        return _FakeWaiter(name, self.waiter_calls)


class _FakeResource:
    def __init__(self, client: _FakeClient) -> None:
        self.meta = type("Meta", (), {"client": client})()


# -- endpoint gating -----------------------------------------------------------


def test_configured_endpoint_reads_env_and_treats_blank_as_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert local.configured_endpoint() is None
    monkeypatch.setenv(local.ENDPOINT_ENV_VAR, "  ")
    assert local.configured_endpoint() is None
    monkeypatch.setenv(local.ENDPOINT_ENV_VAR, " http://localhost:8000 ")
    assert local.configured_endpoint() == "http://localhost:8000"


def test_skip_reason_without_env_var_names_the_env_var() -> None:
    reason = local.skip_reason()
    assert reason is not None
    assert local.ENDPOINT_ENV_VAR in reason
    assert "docs/operations.md" in reason


def test_skip_reason_with_unreachable_endpoint_names_the_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Bind then close a port so the address is (almost certainly) refused.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_endpoint = f"http://127.0.0.1:{probe.getsockname()[1]}"
    probe.close()
    monkeypatch.setenv(local.ENDPOINT_ENV_VAR, dead_endpoint)
    reason = local.skip_reason()
    assert reason is not None
    assert dead_endpoint in reason


def test_skip_reason_none_when_set_and_reachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        monkeypatch.setenv(local.ENDPOINT_ENV_VAR, f"http://127.0.0.1:{listener.getsockname()[1]}")
        assert local.skip_reason() is None
    finally:
        listener.close()


def test_require_local_endpoint_skips_when_unset() -> None:
    with pytest.raises(pytest.skip.Exception):
        local.require_local_endpoint()


# -- probe semantics ------------------------------------------------------------


def test_probe_accepts_listening_port_and_rejects_closed_or_malformed() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    live = f"http://127.0.0.1:{port}"
    assert local.probe_endpoint(live) is True
    listener.close()
    assert local.probe_endpoint(live) is False
    assert local.probe_endpoint("not a url") is False
    assert local.probe_endpoint("") is False


# -- table spec (decision 2's layout) -------------------------------------------


def _spec(name: str) -> local.TableSpec:
    return next(spec for spec in local.TABLE_SPECS if spec.name == name)


def test_seven_tables_with_expected_names() -> None:
    assert [spec.name for spec in local.TABLE_SPECS] == [
        "users",
        "organizations",
        "external_identities",
        "audit_events",
        "api_keys",
        "memberships",
        "unique_constraints",
    ]


def test_record_id_tables_are_pk_keyed_and_unique_constraints_is_key_only() -> None:
    for name in ("users", "organizations", "external_identities", "audit_events", "api_keys"):
        spec = _spec(name)
        assert spec.partition_key == "pk", name
        assert spec.sort_key is None, name
    constraints = _spec("unique_constraints")
    # Key-only is required: GetItem lookups know the full key only as <kind>#<value>,
    # and a sort key would silently defeat the uniqueness the table enforces.
    assert constraints.partition_key == "pk"
    assert constraints.sort_key is None
    assert constraints.indexes == ()


def test_memberships_carries_native_pair_key_and_both_listing_gsis() -> None:
    memberships = _spec("memberships")
    assert (memberships.partition_key, memberships.sort_key) == ("organization_id", "user_id")
    assert {(i.name, i.partition_key, i.sort_key) for i in memberships.indexes} == {
        ("by-organization", "g_org", "g_created"),
        ("by-user", "g_user", "g_org_created"),
    }


def test_api_keys_carries_the_organization_listing_gsi_only() -> None:
    api_keys = _spec("api_keys")
    assert [(i.name, i.partition_key, i.sort_key) for i in api_keys.indexes] == [
        ("by-organization", "g_org", "g_created")
    ]


def test_create_parameters_apply_prefix_string_keys_and_all_projection() -> None:
    payload = _spec("memberships").create_parameters("pfx-")
    assert payload["TableName"] == "pfx-memberships"
    assert payload["BillingMode"] == "PAY_PER_REQUEST"
    assert payload["AttributeDefinitions"] == [
        {"AttributeName": "organization_id", "AttributeType": "S"},
        {"AttributeName": "user_id", "AttributeType": "S"},
        {"AttributeName": "g_org", "AttributeType": "S"},
        {"AttributeName": "g_created", "AttributeType": "S"},
        {"AttributeName": "g_user", "AttributeType": "S"},
        {"AttributeName": "g_org_created", "AttributeType": "S"},
    ]
    assert payload["KeySchema"] == [
        {"AttributeName": "organization_id", "KeyType": "HASH"},
        {"AttributeName": "user_id", "KeyType": "RANGE"},
    ]
    assert {index["IndexName"] for index in payload["GlobalSecondaryIndexes"]} == {
        "by-organization",
        "by-user",
    }
    assert all(
        index["Projection"] == {"ProjectionType": "ALL"}
        for index in payload["GlobalSecondaryIndexes"]
    )


def test_create_parameters_omit_gsis_for_single_key_tables() -> None:
    payload = _spec("users").create_parameters("pfx-")
    assert "GlobalSecondaryIndexes" not in payload
    assert payload["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"}]


# -- prefix and name hygiene -----------------------------------------------------


def test_random_prefixes_are_valid_unique_and_names_in_range() -> None:
    prefixes = {local.random_table_prefix() for _ in range(50)}
    assert len(prefixes) == 50
    for prefix in prefixes:
        assert _valid_table_name(prefix)
        for spec in local.TABLE_SPECS:
            full = f"{prefix}{spec.name}"
            assert _valid_table_name(full)
            assert 3 <= len(full) <= 255


def _valid_table_name(value: str) -> bool:
    return local._TABLE_NAME_PATTERN.match(value) is not None


def test_table_names_are_prefixed_in_spec_order() -> None:
    assert local.table_names("pfx-") == (
        "pfx-users",
        "pfx-organizations",
        "pfx-external_identities",
        "pfx-audit_events",
        "pfx-api_keys",
        "pfx-memberships",
        "pfx-unique_constraints",
    )


# -- lifecycle against an injected fake (no live calls) ---------------------------


def test_create_tables_creates_every_spec_and_waits_for_each() -> None:
    client = _FakeClient()
    local.create_tables("pfx-", resource=_FakeResource(client))
    assert [payload["TableName"] for payload in client.created_payloads] == list(
        local.table_names("pfx-")
    )
    assert [call[:2] for call in client.waiter_calls] == [
        ("table_exists", name) for name in local.table_names("pfx-")
    ]
    _assert_capitalized_waiter_config(client)


def test_delete_tables_deletes_every_spec_and_confirms_gone() -> None:
    client = _FakeClient()
    local.delete_tables("pfx-", resource=_FakeResource(client))
    assert client.deleted_names == list(local.table_names("pfx-"))
    assert [call[0] for call in client.waiter_calls] == ["table_not_exists"] * 7
    _assert_capitalized_waiter_config(client)


def _assert_capitalized_waiter_config(client: _FakeClient) -> None:
    """botocore only honors capitalized Delay/MaxAttempts; lowercase is a
    silent no-op that falls back to the 20s x 25 defaults — pin the shape."""
    assert client.waiter_calls
    for _, _, config in client.waiter_calls:
        assert set(config) == {"Delay", "MaxAttempts"}
        assert config == local.WAITER_CONFIG


def test_delete_tables_tolerates_missing_table_but_propagates_other_errors() -> None:
    missing = local.table_names("pfx-")[0]
    client = _FakeClient(delete_errors={missing: _client_error("ResourceNotFoundException")})
    local.delete_tables("pfx-", resource=_FakeResource(client))
    assert missing not in client.deleted_names  # skipped, teardown stays quiet
    assert len(client.deleted_names) == 6

    hostile = _FakeClient(delete_errors={missing: _client_error("InternalServerError")})
    with pytest.raises(ClientError):
        local.delete_tables("pfx-", resource=_FakeResource(hostile))


# -- resource factory seam ---------------------------------------------------------


def test_make_dynamodb_resource_targets_local_without_network() -> None:
    resource = local.make_dynamodb_resource("http://127.0.0.1:1")  # never contacted
    assert resource.meta.client.meta.endpoint_url == "http://127.0.0.1:1"
    assert resource.meta.client.meta.region_name == local.DEFAULT_REGION
