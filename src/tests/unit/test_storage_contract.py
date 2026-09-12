"""Unit tests for the Phase 02 task-1 storage contract surface.

Covers the task's verify lines:

1. ``StorageError`` hierarchy relationships and the full ``kind``
   discriminator set, including ``entity_id`` for primary-key collisions.
2. ``ProvisionedUser`` is frozen and is a pure caller-echo bundle.
3. A minimal stub class satisfies ``isinstance`` under ``runtime_checkable``;
   a partial stub does not.
4. The protocol exposes exactly the 18 §11/§12 methods, all synchronous, with
   signatures that reference only domain/typing types (no driver types).
5. Subprocess-isolated import check (fresh interpreter, Phase 01 task-6
   precedent): importing ``app.storage.contract`` and ``app.storage`` pulls in
   neither ``sqlite3``, ``boto3``, nor any adapter module. In-process
   ``sys.modules`` assertions would be order-dependent and false-fail in
   Phase 06, so they are deliberately not used.
"""

from __future__ import annotations

import inspect
import os
import subprocess
import sys
import typing
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

import app.storage as storage_package
import app.storage.contract as contract
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

#: Repository root, so the subprocess check imports the same ``app`` package
#: (Phase 01 task-6 precedent).
REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_ROOT = REPO_ROOT / "src"

#: The 18 §11/§12 operations, exactly as the spec sketch names them plus the
#: compound ``provision_user``.
CONTRACT_METHODS = frozenset(
    {
        "create_user",
        "get_user",
        "create_external_identity",
        "get_user_by_external_identity",
        "create_organization",
        "get_organization",
        "list_user_organizations",
        "create_membership",
        "get_membership",
        "list_memberships",
        "delete_membership",
        "create_api_key",
        "get_api_key",
        "get_api_key_by_key_id",
        "list_api_keys",
        "revoke_api_key",
        "append_audit_event",
        "provision_user",
    }
)

#: Every ``kind`` discriminator the vocabulary admits (closed set).
DUPLICATE_KINDS = frozenset(
    {
        "entity_id",
        "external_identity",
        "membership",
        "organization_slug",
        "user_email",
        "api_key_id",
    }
)

#: Modules a contract signature may reference. ``datetime`` appears only as
#: the payload of ``app.models``'s ``UtcDatetime`` alias; ``ProvisionedUser``
#: is this module's own result type.
ALLOWED_ANNOTATION_MODULES = frozenset(
    {
        "app.models",
        "app.models.api_key",
        "app.models.audit_event",
        "app.models.enums",
        "app.models.external_identity",
        "app.models.ids",
        "app.models.membership",
        "app.models.organization",
        "app.models.pagination",
        "app.models.timestamps",
        "app.models.user",
        "app.storage.contract",
        "builtins",
        "collections.abc",
        "datetime",
        "typing",
    }
)

BANNED_ANNOTATION_MODULE_PREFIXES = ("sqlite3", "sqlite", "boto3", "botocore", "sqlalchemy")


# ---------------------------------------------------------------------------
# Deterministic domain builders (literal prefix-valid ids, fixed timestamps —
# the same rule the conformance-suite builders follow).
# ---------------------------------------------------------------------------

_T0 = datetime(2026, 9, 12, 10, 0, 0, tzinfo=UTC)


def make_user() -> User:
    return User(
        id=UserId("usr_test_0001"),
        display_name="Test User",
        email="test@example.com",
        status=UserStatus.ACTIVE,
        created_at=_T0,
        updated_at=_T0,
    )


def make_identity(user: User | None = None) -> ExternalIdentity:
    owner = user or make_user()
    return ExternalIdentity(
        id=ExternalIdentityId("extid_test_0001"),
        user_id=owner.id,
        provider=IdentityProvider.COGNITO,
        provider_subject="11111111-2222-3333-4444-555555555555",
        created_at=_T0,
    )


def make_organization() -> Organization:
    return Organization(
        id=OrganizationId("org_test_0001"),
        name="Test Org",
        slug="test-org",
        type=OrganizationType.PERSONAL,
        status=OrganizationStatus.ACTIVE,
        created_at=_T0,
        updated_at=_T0,
    )


def make_membership() -> Membership:
    return Membership(
        id=MembershipId("mem_test_0001"),
        organization_id=OrganizationId("org_test_0001"),
        user_id=UserId("usr_test_0001"),
        role=MembershipRole.OWNER,
        status=MembershipStatus.ACTIVE,
        created_at=_T0,
    )


def make_audit_event() -> AuditEvent:
    return AuditEvent(
        id=AuditEventId("aud_test_0001"),
        organization_id=OrganizationId("org_test_0001"),
        actor_type="user",
        actor_id=UserId("usr_test_0001"),
        action="user.provisioned",
        created_at=_T0,
    )


def make_api_key() -> ApiKey:
    return ApiKey(
        id=ApiKeyId("key_test_0001"),
        organization_id=OrganizationId("org_test_0001"),
        created_by_user_id=UserId("usr_test_0001"),
        name="ci",
        key_id="01JTESTKEYID",
        key_prefix="fn_live_01J",
        secret_hash="a" * 64,
        environment=ApiKeyEnvironment.LIVE,
        scopes=["vispector:inspection:run"],
        status=ApiKeyStatus.ACTIVE,
        created_at=_T0,
    )


def _stub_class(skip: str | None = None) -> type:
    """Build a class implementing every contract method (or all but ``skip``)."""

    def stub(self: object, *args: object, **kwargs: object) -> None:
        return None

    members = {name: stub for name in CONTRACT_METHODS if name != skip}
    return type("StubStorage", (), members)


def _annotation_modules(hint: object) -> set[str]:
    """Collect the modules an annotation (recursively) is defined in."""
    modules: set[str] = set()
    pending: list[object] = [hint]
    while pending:
        current = pending.pop()
        if typing.get_origin(current) is typing.Annotated:
            # Unwrap ``Annotated`` to its payload; the metadata are callables.
            pending.append(typing.get_args(current)[0])
            continue
        origin = typing.get_origin(current)
        if origin is not None:
            pending.extend(typing.get_args(current))
            current = origin
        module = getattr(current, "__module__", None)
        if module is not None:
            modules.add(module)
    return modules


# ---------------------------------------------------------------------------
# 1. Error vocabulary: hierarchy and discriminator set
# ---------------------------------------------------------------------------


def test_storage_error_is_the_common_base() -> None:
    assert issubclass(contract.StorageError, Exception)
    for cls in (
        contract.EntityNotFoundError,
        contract.DuplicateEntityError,
        contract.ReferenceNotFoundError,
        contract.InvalidCursorError,
    ):
        assert issubclass(cls, contract.StorageError), cls


def test_duplicate_external_identity_nests_under_duplicate_entity() -> None:
    assert issubclass(contract.DuplicateExternalIdentityError, contract.DuplicateEntityError)
    assert issubclass(contract.DuplicateExternalIdentityError, contract.StorageError)
    # Catchable through the generic path adapters/services will use.
    with pytest.raises(contract.DuplicateEntityError):
        raise contract.DuplicateExternalIdentityError(existing_user_id=UserId("usr_test_0002"))


@pytest.mark.parametrize(
    ("leaf", "unrelated"),
    [
        (contract.EntityNotFoundError, contract.DuplicateEntityError),
        (contract.ReferenceNotFoundError, contract.EntityNotFoundError),
        (contract.InvalidCursorError, contract.DuplicateEntityError),
        (contract.DuplicateEntityError, contract.InvalidCursorError),
        (contract.DuplicateExternalIdentityError, contract.EntityNotFoundError),
    ],
)
def test_error_classes_are_distinct_branches(leaf: type, unrelated: type) -> None:
    assert not issubclass(leaf, unrelated)


def test_kind_discriminator_set_is_closed_and_stable() -> None:
    assert {kind.value for kind in contract.DuplicateEntityKind} == DUPLICATE_KINDS
    assert contract.DuplicateEntityKind.ENTITY_ID == "entity_id"
    assert contract.DuplicateEntityKind.API_KEY_ID == "api_key_id"


def test_duplicate_entity_error_accepts_enum_and_string_kind() -> None:
    from_enum = contract.DuplicateEntityError(contract.DuplicateEntityKind.USER_EMAIL)
    from_string = contract.DuplicateEntityError("user_email", "email taken")
    assert from_enum.kind is contract.DuplicateEntityKind.USER_EMAIL
    assert from_string.kind is contract.DuplicateEntityKind.USER_EMAIL
    assert from_string.args[0] == "email taken"
    # Default message names the discriminator and nothing adapter-specific.
    assert "user_email" in str(from_enum)
    assert "sql" not in str(from_enum).lower()


@pytest.mark.parametrize("kind", sorted(DUPLICATE_KINDS))
def test_every_kind_discriminator_is_constructible(kind: str) -> None:
    error = contract.DuplicateEntityError(kind)
    assert error.kind is contract.DuplicateEntityKind(kind)


def test_unknown_kind_discriminator_is_rejected() -> None:
    with pytest.raises(ValueError, match="DuplicateEntityKind"):
        contract.DuplicateEntityError("not_a_real_kind")


def test_duplicate_external_identity_error_carries_existing_user_id() -> None:
    resolved = contract.DuplicateExternalIdentityError(existing_user_id=UserId("usr_winner_1"))
    unresolved = contract.DuplicateExternalIdentityError()
    assert resolved.kind is contract.DuplicateEntityKind.EXTERNAL_IDENTITY
    assert resolved.existing_user_id == "usr_winner_1"
    assert isinstance(resolved.existing_user_id, UserId)
    # An unresolvable winner is a legitimate outcome, pinned as ``None``.
    assert unresolved.existing_user_id is None


def test_error_messages_do_not_require_adapter_detail() -> None:
    # The vocabulary is constructible with a plain message only, so adapters
    # never need driver text to name the conflict.
    for error in (
        contract.EntityNotFoundError("user not found"),
        contract.ReferenceNotFoundError("unknown organization"),
        contract.InvalidCursorError("cursor failed to decode"),
    ):
        assert isinstance(error.args[0], str)


# ---------------------------------------------------------------------------
# 2. ProvisionedUser: frozen caller-echo bundle
# ---------------------------------------------------------------------------


def _bundle(**overrides: object) -> contract.ProvisionedUser:
    values: dict[str, object] = {
        "user": make_user(),
        "identity": make_identity(),
        "organization": make_organization(),
        "membership": make_membership(),
        "audit_events": [make_audit_event()],
    }
    values.update(overrides)
    return contract.ProvisionedUser(**values)  # type: ignore[arg-type]


def test_provisioned_user_fields_are_the_contract_components() -> None:
    assert set(contract.ProvisionedUser.model_fields) == {
        "user",
        "identity",
        "organization",
        "membership",
        "audit_events",
    }


def test_provisioned_user_echoes_the_caller_objects_unchanged() -> None:
    user, identity, organization, membership = (
        make_user(),
        make_identity(),
        make_organization(),
        make_membership(),
    )
    audit = make_audit_event()
    bundle = _bundle(user=user, identity=identity, organization=organization, membership=membership)
    # "Storage mints nothing and does not re-read": the very objects passed in.
    assert bundle.user is user
    assert bundle.identity is identity
    assert bundle.organization is organization
    assert bundle.membership is membership
    assert bundle.audit_events == (audit,)


def test_provisioned_user_is_frozen_and_rejects_extras() -> None:
    bundle = _bundle()
    with pytest.raises(ValidationError):
        bundle.user = make_user()  # type: ignore[misc]
    with pytest.raises(ValidationError):
        _bundle(rows=[{"leak": True}])  # type: ignore[call-arg]


def test_provisioned_user_accepts_any_sequence_of_audit_events() -> None:
    audit = make_audit_event()
    assert _bundle(audit_events=(audit,)).audit_events == (audit,)
    assert _bundle(audit_events=(a for a in (audit,))).audit_events == (audit,)


# ---------------------------------------------------------------------------
# 3. runtime_checkable protocol conformance
# ---------------------------------------------------------------------------


def test_minimal_stub_satisfies_isinstance() -> None:
    assert isinstance(_stub_class()(), contract.Storage)


def test_partial_stub_does_not_satisfy_isinstance() -> None:
    for missing in ("append_audit_event", "provision_user", "get_user"):
        assert not isinstance(_stub_class(skip=missing)(), contract.Storage), missing


def test_plain_object_does_not_satisfy_isinstance() -> None:
    assert not isinstance(object(), contract.Storage)


# ---------------------------------------------------------------------------
# 4. Protocol surface: 18 methods, sync, domain-only types
# ---------------------------------------------------------------------------


def test_protocol_exposes_exactly_the_18_contract_methods() -> None:
    members = typing.get_protocol_members(contract.Storage)
    assert members == set(CONTRACT_METHODS)
    assert len(members) == 18


@pytest.mark.parametrize("name", sorted(CONTRACT_METHODS))
def test_every_contract_method_is_synchronous_and_documented(name: str) -> None:
    method = getattr(contract.Storage, name)
    assert not inspect.iscoroutinefunction(method), name
    assert method.__doc__, f"{name} must pin its semantics in a docstring"


@pytest.mark.parametrize("name", sorted(CONTRACT_METHODS))
def test_signatures_reference_only_domain_types(name: str) -> None:
    hints = typing.get_type_hints(getattr(contract.Storage, name), include_extras=True)
    for parameter, hint in hints.items():
        for module in _annotation_modules(hint):
            banned = module.startswith(BANNED_ANNOTATION_MODULE_PREFIXES)
            assert not banned, (name, parameter, module)
            assert module in ALLOWED_ANNOTATION_MODULES, (name, parameter, module)


def test_get_user_by_external_identity_is_the_resolve_operation() -> None:
    # Pinned in the contract docstring so Phase 06 does not add a 19th method.
    doc = contract.Storage.get_user_by_external_identity.__doc__ or ""
    assert "resolve_external_identity" in doc
    assert "no 19th method" in doc


def test_docstrings_pin_the_required_semantics() -> None:
    # Adapters must not reinterpret these; the breakdown pins them here.
    assert "entity_id" in (contract.Storage.create_user.__doc__ or "")
    assert "first-write-wins" in (contract.Storage.revoke_api_key.__doc__ or "")
    assert "active" in (contract.Storage.list_user_organizations.__doc__ or "")
    assert "not** filtered" in (contract.Storage.get_api_key.__doc__ or "")
    assert "fully rolled back" in (contract.Storage.provision_user.__doc__ or "")
    assert "Returns ``None``" in (contract.Storage.append_audit_event.__doc__ or "")


# ---------------------------------------------------------------------------
# 5. Pinned signature shapes (reviewer notes)
# ---------------------------------------------------------------------------


def test_append_audit_event_is_pinned_to_none() -> None:
    hints = typing.get_type_hints(contract.Storage.append_audit_event)
    assert hints["return"] is type(None)
    signature = inspect.signature(contract.Storage.append_audit_event)
    assert list(signature.parameters) == ["self", "audit_event"]


def test_provision_user_audit_events_is_required_keyword_only() -> None:
    parameters = inspect.signature(contract.Storage.provision_user).parameters
    audit_events = parameters["audit_events"]
    assert audit_events.kind is inspect.Parameter.KEYWORD_ONLY
    assert audit_events.default is inspect.Parameter.empty
    # No defaults anywhere: silently skipping §16 events must be impossible.
    assert all(p.default is inspect.Parameter.empty for p in parameters.values())


def test_multi_value_lookups_are_keyword_only() -> None:
    for name in ("get_user_by_external_identity", "get_membership", "delete_membership"):
        parameters = inspect.signature(getattr(contract.Storage, name)).parameters
        positional = [
            parameter
            for parameter in parameters
            if parameter != "self"
            and parameters[parameter].kind is not inspect.Parameter.KEYWORD_ONLY
        ]
        assert positional == [], name
    revoked_at = inspect.signature(contract.Storage.revoke_api_key).parameters["revoked_at"]
    assert revoked_at.kind is inspect.Parameter.KEYWORD_ONLY
    assert revoked_at.default is inspect.Parameter.empty


def test_membership_lookups_are_keyed_by_the_domain_tuple() -> None:
    # The ``mem_`` record id is never a lookup key above storage (AGENTS.md).
    for name in ("get_membership", "delete_membership"):
        parameters = inspect.signature(getattr(contract.Storage, name)).parameters
        assert set(parameters) == {"self", "organization_id", "user_id"}, name


def test_key_read_methods_are_disambiguated_by_type() -> None:
    by_identity = typing.get_type_hints(contract.Storage.get_api_key)["api_key_id"]
    by_segment = typing.get_type_hints(contract.Storage.get_api_key_by_key_id)["key_id"]
    assert by_identity is ApiKeyId
    assert by_segment is not by_identity


# ---------------------------------------------------------------------------
# 6. Package exports: contract symbols only, no adapter import
# ---------------------------------------------------------------------------


def test_package_reexports_contract_symbols_only() -> None:
    assert set(storage_package.__all__) == set(contract.__all__)
    for symbol in storage_package.__all__:
        assert getattr(storage_package, symbol) is getattr(contract, symbol), symbol
        assert symbol in vars(contract), symbol


def test_importing_the_contract_never_loads_adapters_or_drivers() -> None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env["PYTHONPATH"] = str(SRC_ROOT)
    probe = """
import sys
import app.storage
import app.storage.contract
for leaked in (
    "sqlite3",
    "boto3",
    "botocore",
    "app.storage.sqlite",
    "app.storage.dynamodb",
    "app.storage.memory",
):
    assert leaked not in sys.modules, leaked
print("clean")
"""
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"subprocess import check failed: {result.stderr}"
    assert result.stdout.strip() == "clean"
