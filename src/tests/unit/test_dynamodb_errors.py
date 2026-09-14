"""Unit proofs for DynamoDB error translation (Phase 06 task 2).

The classifier is a **pure function over parsed reason dicts**, so every
positional failure mode is exercised with synthetic payloads — no Docker, no
live calls, and no botocore object beyond a ``ClientError`` factory. Proven
here (breakdown decision 3):

- The first ``ConditionalCheckFailed`` in submission order decides the error
  (multi-failure priority), mapped through the positionally-aligned descriptor.
- A ``membership`` base put maps to the ``membership`` kind (the native org/user
  pair), while every other base put maps to ``entity_id``.
- ``provision_user`` email/identity-tuple failures map to the converge error.
- A parent ``ConditionCheck`` failure maps to ``ReferenceNotFoundError``.
- Transient ``TransactionConflict`` yields a retry verdict; ``execute_transaction``
  re-submits a bounded number of times and, on exhaustion, raises the base
  ``StorageError``.
- Throughput faults and unknown codes become the base ``StorageError``.
- No translated message ever contains a table name, region, or request id.
"""

from __future__ import annotations

from typing import Any

import pytest
from botocore.exceptions import ClientError

import app.storage.contract as contract
from app.storage.dynamodb import (
    MAX_TRANSACTION_ATTEMPTS,
    RETRY,
    DuplicateConflict,
    IdentityRaceConflict,
    ReferenceConflict,
    _RetrySentinel,
    classify_cancellation_reasons,
    classify_client_error,
    execute_transaction,
)

# Hostile driver text planted in every synthetic payload: none of it may appear
# in a translated error (breakdown decision 3: fixed, log-safe messages).
_LEAKY = "table feednow-prod-users in us-east-1 req 4A7B-REQUEST-ID"

#: Short alias for the frozen conflict-kind enum (keeps positional cases terse).
Kind = contract.DuplicateEntityKind


def _reason(code: str) -> dict[str, Any]:
    return {"Code": code, "Message": _LEAKY}


def _canceled(reasons: list[dict[str, Any]]) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": "TransactionCanceledException", "Message": _LEAKY},
            "CancellationReasons": reasons,
        },
        "TransactWriteItems",
    )


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": _LEAKY}}, "UpdateItem")


def _assert_no_leak(error: Exception) -> None:
    text = str(error)
    for fragment in ("feednow-prod-users", "us-east-1", "4A7B-REQUEST-ID", _LEAKY):
        assert fragment not in text


# -- positional classification -------------------------------------------------


def test_no_error_reasons_are_skipped() -> None:
    reasons = [_reason("None"), _reason("None")]
    assert isinstance(
        classify_cancellation_reasons(reasons, [DuplicateConflict(Kind.ENTITY_ID)] * 2),
        contract.StorageError,
    )


def test_first_conditional_check_failed_in_submission_order_decides() -> None:
    # Two conditional failures: the earlier submission position wins, even
    # though a TransactionConflict sits between them.
    reasons = [
        _reason("None"),
        _reason("ConditionalCheckFailed"),
        _reason("TransactionConflict"),
        _reason("ConditionalCheckFailed"),
    ]
    descriptors = [
        ReferenceConflict(),
        DuplicateConflict(Kind.ORGANIZATION_SLUG),
        DuplicateConflict(Kind.USER_EMAIL),
        DuplicateConflict(Kind.API_KEY_ID),
    ]
    error = classify_cancellation_reasons(reasons, descriptors)
    assert isinstance(error, contract.DuplicateEntityError)
    assert error.kind is Kind.ORGANIZATION_SLUG
    _assert_no_leak(error)


def test_membership_base_put_maps_to_membership_kind_exception() -> None:
    # Decision 2/3: the membership base put's native PK+SK condition enforces
    # the org/user pair -> ``membership``, unlike every other base put.
    reasons = [_reason("ConditionalCheckFailed")]
    error = classify_cancellation_reasons(reasons, [DuplicateConflict(Kind.MEMBERSHIP)])
    assert isinstance(error, contract.DuplicateEntityError)
    assert error.kind is Kind.MEMBERSHIP
    _assert_no_leak(error)


def test_record_id_base_put_maps_to_entity_id() -> None:
    error = classify_cancellation_reasons(
        [_reason("ConditionalCheckFailed")],
        [DuplicateConflict(Kind.ENTITY_ID)],
    )
    assert isinstance(error, contract.DuplicateEntityError)
    assert error.kind is Kind.ENTITY_ID


def test_parent_condition_check_maps_to_reference_not_found() -> None:
    error = classify_cancellation_reasons(
        [_reason("ConditionalCheckFailed")], [ReferenceConflict()]
    )
    assert isinstance(error, contract.ReferenceNotFoundError)
    assert not isinstance(error, contract.DuplicateEntityError)
    _assert_no_leak(error)


def test_identity_race_descriptor_maps_to_converge_error() -> None:
    error = classify_cancellation_reasons(
        [_reason("ConditionalCheckFailed")], [IdentityRaceConflict()]
    )
    assert isinstance(error, contract.DuplicateExternalIdentityError)
    assert error.kind is Kind.EXTERNAL_IDENTITY
    assert error.existing_user_id is None  # resolved by the operation (task 6)


def test_conditional_check_with_no_descriptor_is_generic_storage_error() -> None:
    # Programming error (misaligned descriptor list), never a guessed conflict.
    error = classify_cancellation_reasons([_reason("ConditionalCheckFailed")], [])
    assert type(error) is contract.StorageError
    _assert_no_leak(error)


# -- transient vs throughput vs unknown ---------------------------------------


def test_transaction_conflict_yields_retry_verdict() -> None:
    outcome = classify_cancellation_reasons([_reason("TransactionConflict")], [])
    assert outcome is RETRY


def test_throughput_code_maps_to_storage_error() -> None:
    error = classify_cancellation_reasons([_reason("ProvisionedThroughputExceeded")], [])
    assert type(error) is contract.StorageError
    _assert_no_leak(error)


def test_unknown_fault_code_maps_to_storage_error() -> None:
    error = classify_cancellation_reasons([_reason("SomethingWeird")], [])
    assert type(error) is contract.StorageError
    _assert_no_leak(error)


# -- classify_client_error (single ClientError dispatch) -----------------------


def test_client_error_delegates_cancellation_to_reason_classifier() -> None:
    exc = _canceled([_reason("ConditionalCheckFailed")])
    error = classify_client_error(exc, [DuplicateConflict(Kind.USER_EMAIL)])
    assert isinstance(error, contract.DuplicateEntityError)
    assert error.kind is Kind.USER_EMAIL


def test_single_item_transient_client_error_yields_retry() -> None:
    assert classify_client_error(_client_error("TransactionConflictException"), []) is RETRY
    assert classify_client_error(_client_error("TransactionInProgressException"), []) is RETRY


def test_single_item_throughput_and_unknown_map_to_storage_error() -> None:
    for code in (
        "ThrottlingException",
        "ProvisionedThroughputExceededException",
        "ValidationException",
    ):
        error = classify_client_error(_client_error(code), [])
        assert type(error) is contract.StorageError, code
        _assert_no_leak(error)


# -- execute_transaction: bounded retry, converge, propagate ------------------


class _ScriptedSubmit:
    """Raises the queued outcome (ClientError) or returns None to mean success."""

    def __init__(self, outcomes: list[Any]) -> None:
        self._outcomes = outcomes
        self.calls = 0

    def __call__(self) -> None:
        self.calls += 1
        outcome = self._outcomes.pop(0) if self._outcomes else None
        if isinstance(outcome, BaseException):
            raise outcome
        # A None outcome means the transaction committed.


def test_transient_conflict_is_retried_then_converges_on_success() -> None:
    submit = _ScriptedSubmit([_canceled([_reason("TransactionConflict")]), None])
    execute_transaction(submit, [])
    assert submit.calls == 2  # one retry, then the winner's committed rows are visible


def test_retry_reclassifies_a_stable_conflict_on_a_later_attempt() -> None:
    # First submission loses to a transient conflict; the retry then hits the
    # winner's committed constraint and reclassifies to a stable domain error
    # (breakdown verify: "bounded retry -> reclassify").
    submit = _ScriptedSubmit(
        [
            _canceled([_reason("TransactionConflict")]),
            _canceled([_reason("ConditionalCheckFailed")]),
        ],
    )
    descriptors = [DuplicateConflict(contract.DuplicateEntityKind.USER_EMAIL)]
    with pytest.raises(contract.DuplicateEntityError) as excinfo:
        execute_transaction(submit, descriptors)
    assert excinfo.value.kind is contract.DuplicateEntityKind.USER_EMAIL
    assert submit.calls == 2


def test_stable_conflict_propagates_without_retry() -> None:
    submit = _ScriptedSubmit(
        [_canceled([_reason("ConditionalCheckFailed")])],
    )
    descriptors = [DuplicateConflict(Kind.ORGANIZATION_SLUG)]
    with pytest.raises(contract.DuplicateEntityError) as excinfo:
        execute_transaction(submit, descriptors)
    assert excinfo.value.kind is Kind.ORGANIZATION_SLUG
    assert submit.calls == 1  # a stable conflict will recur: no retry


def test_exhausted_retries_become_storage_error() -> None:
    always_conflict = [
        _canceled([_reason("TransactionConflict")]) for _ in range(MAX_TRANSACTION_ATTEMPTS)
    ]
    submit = _ScriptedSubmit(always_conflict)
    with pytest.raises(contract.StorageError) as excinfo:
        execute_transaction(submit, [])
    assert submit.calls == MAX_TRANSACTION_ATTEMPTS
    assert type(excinfo.value) is contract.StorageError
    _assert_no_leak(excinfo.value)


def test_success_makes_no_classification_and_no_error() -> None:
    submit = _ScriptedSubmit([None])
    execute_transaction(submit, [ReferenceConflict()])
    assert submit.calls == 1


def test_retry_sentinel_is_not_an_error_class() -> None:
    # Guards the contract: RETRY is a control-flow verdict, never raised above
    # the adapter as a StorageError subclass.
    assert isinstance(RETRY, _RetrySentinel)
    assert not isinstance(RETRY, contract.StorageError)
