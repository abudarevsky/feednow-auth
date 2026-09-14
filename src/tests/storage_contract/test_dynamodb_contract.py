"""DynamoDB Local conformance entry point for the Phase 02 storage suite (task 8).

This module is the documented replication of ``test_sqlite_contract.py`` for
the second adapter (Phase 06, AC 2): it provides the ``storage`` fixture
required by ``suite.py``'s fixture contract — an initialized adapter with all
tables empty, **per test** — by creating the seven adapter tables under a
fresh random prefix (harness decision 8) and deleting them on teardown, and
it re-exports every suite case unchanged so pytest collects the same 60
adapter-neutral behaviors that SQLite runs. ``suite.py`` is consumed as a
frozen oracle: if a case fails here, the **adapter** changes (the entry-local
hash pin below proves the bytes never drift).

Marker-gated (``dynamodb_local``): every case that takes the ``storage``
fixture skips with an explicit reason unless
``FEEDNOW_DYNAMODB_LOCAL_ENDPOINT`` is set and reachable, so the default
``uv run pytest`` stays green on machines without Docker
(``docs/operations.md`` carries the run command). The static entry-local
proofs below need no server and run in every configuration.

The entry-local proofs pin this file's coupling rules: the shared suite file
is byte-identical to the one the SQLite entry runs (sha256 against the
Phase 06 baseline), the fixture really starts empty, and every suite case
couples only to the ``storage`` fixture — no adapter-conditional test logic
exists anywhere in the suite.
"""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.models.ids import UserId
from app.storage.contract import EntityNotFoundError, Storage

# Re-export the adapter-neutral cases; pytest collects them from this
# module's namespace with the fixture below — the exact documented
# suite-reuse pattern of the SQLite entry, against this adapter's fixture.
from storage_contract.suite import *  # noqa: F403
from tests.support import dynamodb_local as local

pytestmark = pytest.mark.dynamodb_local

SUITE_PATH: Path = Path(__file__).resolve().parent / "suite.py"

#: sha256 of ``suite.py``'s exact bytes at the Phase 06 baseline (HEAD when
#: this entry was written; the file is untouched since Phase 04 task 1).
#: AC 2: any drift here means the shared suite was edited to fit DynamoDB
#: instead of the adapter changing — this pin fails loudly first.
SUITE_SHA256_AT_BASELINE = "025c879c6a260b6f30a9d22f20129ce82371eaea084a7392958ca4f568f2ddc9"


@pytest.fixture
def storage() -> Iterator[Storage]:
    """Fresh initialized DynamoDB adapter with all seven tables empty (per test).

    Harness decision 8: a new random table prefix per test, created empty and
    deleted on teardown (no truncation races). The adapter gets its **own**
    boto3 resource so ``close()`` on teardown cannot take the harness client
    that deletes the tables with it. The isinstance check is the
    ``runtime_checkable`` stub proof of the fixture contract.
    """
    endpoint = local.require_local_endpoint()
    harness = local.make_dynamodb_resource(endpoint)
    prefix = local.random_table_prefix()
    adapter: Storage | None = None
    try:
        local.create_tables(prefix, resource=harness)
        adapter = local.make_dynamodb_storage(
            prefix, resource=local.make_dynamodb_resource(endpoint)
        )
        assert isinstance(adapter, Storage)
        yield adapter
    finally:
        # Cleanup covers mid-setup failures too: ``delete_tables`` tolerates
        # partially created table sets, and a raising ``close()`` must never
        # skip the table deletion.
        try:
            if adapter is not None:
                adapter.close()
        finally:
            local.delete_tables(prefix, resource=harness)


# ---------------------------------------------------------------------------
# Harness guarantees (DynamoDB entry; not part of the adapter-neutral suite)
# ---------------------------------------------------------------------------


def test_suite_file_is_byte_identical_to_the_baseline_pin() -> None:
    # The shared suite this entry executes is the exact file the SQLite entry
    # executes, unchanged since the Phase 06 baseline (AC 2's "same
    # conformance cases" made checkable, not aspirational).
    from storage_contract import suite

    assert Path(suite.__file__).resolve() == SUITE_PATH
    digest = hashlib.sha256(SUITE_PATH.read_bytes()).hexdigest()
    assert digest == SUITE_SHA256_AT_BASELINE, (
        "suite.py bytes drifted from the Phase 06 baseline; the adapter must "
        "change to satisfy the shared suite, never the other way around"
    )


def test_storage_fixture_starts_with_empty_tables(storage: Storage) -> None:
    # The suite's builders use literal ids; a fresh fixture must not see any
    # of them persisted (per-test isolation, per the fixture contract).
    for user_id in ("usr_test_0001", "usr_test_0002"):
        with pytest.raises(EntityNotFoundError):
            storage.get_user(UserId(user_id))


def test_every_suite_case_couples_only_to_the_storage_fixture() -> None:
    from storage_contract import suite

    cases = [value for name, value in vars(suite).items() if name.startswith("test_")]
    assert cases, "suite.py must define conformance cases"
    for case in cases:
        parameters = list(inspect.signature(case).parameters)
        assert parameters == ["storage"], case.__name__
