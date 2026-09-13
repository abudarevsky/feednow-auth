"""Unit tests for Phase 03 task 1 application ID minting (:mod:`app.services.idgen`).

Verify lines covered (per the Phase 03 breakdown, task 1):

1. Each minter returns the correct concrete typed ID class with a valid prefix.
2. 10,000 samples per minter are unique.
3. No minter accepts or derives from email/``sub``/provider input (zero-argument
   signatures, input-rejecting calls, a stubbed entropy source proving ``uuid4``
   is the only input, and an AST guard over the module body).
4. The Phase 05 boundary holds: this module mints no ``key_``/``key_id`` values.
"""

from __future__ import annotations

import ast
import inspect
import re
import uuid
from pathlib import Path

import pytest

import app.services.idgen as idgen
from app.models.ids import (
    ID_SUFFIX_PATTERN,
    MAX_ID_LENGTH,
    ApiKeyId,
    ApplicationId,
    AuditEventId,
    ExternalIdentityId,
    MembershipId,
    OrganizationId,
    RecordId,
    UserId,
)
from app.services.idgen import (
    new_audit_event_id,
    new_external_identity_id,
    new_membership_id,
    new_organization_id,
    new_user_id,
)

MINTERS: list[tuple[object, type, str]] = [
    (new_user_id, UserId, "usr"),
    (new_organization_id, OrganizationId, "org"),
    (new_external_identity_id, ExternalIdentityId, "extid"),
    (new_membership_id, MembershipId, "mem"),
    (new_audit_event_id, AuditEventId, "aud"),
]

#: Application identities may surface as ``actor_id``; record IDs may not.
APPLICATION_MINTERS = {new_user_id, new_organization_id}

#: Uniqueness sample size pinned by the task's verify line.
SAMPLES = 10_000

# -- 1. Concrete type and prefix validity ----------------------------------


@pytest.mark.parametrize(("minter", "id_class", "prefix"), MINTERS)
def test_minter_returns_expected_concrete_type(minter, id_class, prefix):
    value = minter()
    assert type(value) is id_class
    assert isinstance(value, str)


@pytest.mark.parametrize(("minter", "id_class", "prefix"), MINTERS)
def test_minted_id_has_valid_prefix_and_shape(minter, id_class, prefix):
    value = minter()
    assert value.startswith(f"{prefix}_")
    suffix = value.removeprefix(f"{prefix}_")
    assert re.fullmatch(ID_SUFFIX_PATTERN, suffix) is not None
    assert len(value) <= MAX_ID_LENGTH


@pytest.mark.parametrize(("minter", "id_class", "prefix"), MINTERS)
def test_minted_id_is_uuid4_hex_suffix(minter, id_class, prefix):
    value = minter()
    suffix = value.removeprefix(f"{prefix}_")
    assert re.fullmatch(r"[0-9a-f]{32}", suffix) is not None


@pytest.mark.parametrize(("minter", "id_class", "prefix"), MINTERS)
def test_minters_respect_the_application_vs_record_split(minter, id_class, prefix):
    value = minter()
    if minter in APPLICATION_MINTERS:
        assert isinstance(value, ApplicationId)
        assert not isinstance(value, RecordId)
    else:
        assert isinstance(value, RecordId)
        assert not isinstance(value, ApplicationId)


@pytest.mark.parametrize(("minter", "id_class", "prefix"), MINTERS)
def test_minted_id_round_trips_through_the_value_type(minter, id_class, prefix):
    value = minter()
    assert id_class(value) == value


# -- 2. Uniqueness ---------------------------------------------------------


@pytest.mark.parametrize(("minter", "id_class", "prefix"), MINTERS)
def test_minter_is_unique_over_10k_samples(minter, id_class, prefix):
    samples = [minter() for _ in range(SAMPLES)]
    assert len(set(samples)) == SAMPLES


@pytest.mark.parametrize(("minter", "id_class", "prefix"), MINTERS)
def test_minter_never_repeats_the_previous_value(minter, id_class, prefix):
    assert minter() != minter()


# -- 3. No email/sub/provider input ---------------------------------------


@pytest.mark.parametrize(("minter", "id_class", "prefix"), MINTERS)
def test_minters_take_no_parameters(minter, id_class, prefix):
    signature = inspect.signature(minter, eval_str=True)
    assert list(signature.parameters) == []
    assert signature.return_annotation is id_class


@pytest.mark.parametrize(("minter", "id_class", "prefix"), MINTERS)
def test_minters_reject_positional_input(minter, id_class, prefix):
    with pytest.raises(TypeError):
        minter("someone@example.com")  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        minter("provider", "subject-123")  # type: ignore[call-arg]


@pytest.mark.parametrize(("minter", "id_class", "prefix"), MINTERS)
def test_minter_derives_only_from_uuid4(minter, id_class, prefix, monkeypatch):
    """With entropy pinned, output is fully determined: nothing else feeds in."""
    fixed = uuid.UUID("00112233445566778899aabbccddeeff")
    monkeypatch.setattr(idgen.uuid, "uuid4", lambda: fixed)
    assert minter() == id_class(f"{prefix}_{fixed.hex}")


def test_module_has_no_non_minter_public_helpers_with_arguments():
    """Every public callable in :mod:`app.services.idgen` is zero-argument."""
    public_callables = [
        obj for name in idgen.__all__ if (obj := getattr(idgen, name)) is not None and callable(obj)
    ]
    assert public_callables
    for obj in public_callables:
        assert list(inspect.signature(obj, eval_str=True).parameters) == []


# -- 4. Phase 05 boundary (key_/key_id stay out of Phase 03) ---------------


def test_module_exports_exactly_the_five_phase_03_minters():
    assert sorted(idgen.__all__) == sorted(
        [
            "new_audit_event_id",
            "new_external_identity_id",
            "new_membership_id",
            "new_organization_id",
            "new_user_id",
        ]
    )


def test_no_api_key_minter_is_exported():
    assert not hasattr(idgen, "new_api_key_id")
    assert not hasattr(idgen, "new_key_id")
    assert ApiKeyId not in {id_class for _, id_class, _ in MINTERS}


def test_module_docstring_records_the_deferral_and_phase_05_boundary():
    doc = idgen.__doc__ or ""
    assert "deferral" in doc
    assert "Phase 05" in doc
    assert "key_id" in doc


def test_source_does_not_reference_identity_provider_inputs():
    """AST guard: outside the module docstring, no email/sub/provider concept appears.

    The minters are pure entropy functions, so the module body must not name or
    string-reference provider identity material at all.
    """
    tree = ast.parse(Path(idgen.__file__).read_text(encoding="utf-8"))
    body = tree.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]  # drop the module docstring, which documents the boundary

    observed: list[str] = []
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            observed.append(node.value)
        elif isinstance(node, (ast.Name, ast.Attribute)):
            target = node.id if isinstance(node, ast.Name) else node.attr
            observed.append(target)
        elif isinstance(node, ast.ImportFrom):
            observed.append(node.module or "")
            observed.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            observed.extend(alias.name for alias in node.names)

    text = " ".join(observed).lower()
    for token in ("email", "provider", "subject", "cognito", "shopify"):
        assert token not in text
