"""SQLite conformance entry point for the Phase 02 storage suite (task 3).

This module is the only SQLite-specific half of the harness: it provides the
``storage`` fixture required by ``suite.py``'s fixture contract (an
initialized adapter with all tables empty, per test — here, a fresh temp
file through the documented factory) and re-exports every suite case so
pytest collects it. Phase 06 replicates *this file* for DynamoDB Local and
runs ``suite.py`` unchanged.

The harness tests below also pin the suite's isolation rules: ``suite.py``
imports only ``app.storage.contract``/``app.models`` (AST + fresh-interpreter
proof) and couples to SQLite solely through the ``storage`` fixture (every
case takes exactly that one fixture argument).
"""

from __future__ import annotations

import ast
import inspect
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.models.ids import UserId
from app.storage.contract import EntityNotFoundError, Storage
from app.storage.sqlite import open_sqlite_storage

# Re-export the adapter-neutral cases; pytest collects them from this
# module's namespace with the fixture below (the documented suite-reuse
# pattern — Phase 06 does the same against its own ``storage`` fixture).
from storage_contract.suite import *  # noqa: F403

SUITE_PATH: Path = Path(__file__).resolve().parent / "suite.py"
SRC_ROOT: Path = Path(__file__).resolve().parents[2]
TESTS_ROOT: Path = Path(__file__).resolve().parents[1]

#: Everything ``suite.py`` may import: the contract, the domain models, and
#: these stdlib/pytest helpers (``threading`` is needed by task 5's barrier
#: concurrency cases, ``collections.abc`` by task 8's traversal helper; the
#: suite docstring's "plus pytest/stdlib" rule). ``app.storage.*`` adapters
#: and drivers are banned by name below as well, so a typo cannot widen the
#: ``app.*`` roots.
SUITE_ALLOWED_IMPORTS = frozenset(
    {
        "__future__",
        "collections.abc",
        "datetime",
        "pytest",
        "threading",
        "app.storage.contract",
    }
)
SUITE_ALLOWED_IMPORT_PREFIXES = ("app.models",)
BANNED_IMPORT_SUBSTRINGS = ("sqlite", "boto", "sqlalchemy", "dynamodb")


@pytest.fixture
def storage(tmp_path: Path) -> Iterator[Storage]:
    """Fresh initialized SQLite adapter with all tables empty (per test)."""
    adapter = open_sqlite_storage(tmp_path / "conformance.sqlite")
    # Fixture contract for Phase 06: an initialized, ``Storage``-compatible
    # adapter. The isinstance check is the runtime_checkable stub check.
    assert isinstance(adapter, Storage)
    yield adapter
    adapter.close()


# ---------------------------------------------------------------------------
# Harness guarantees (SQLite entry; not part of the adapter-neutral suite)
# ---------------------------------------------------------------------------


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


def _suite_imported_modules() -> set[str]:
    """Collect every module name imported by ``suite.py`` (statically)."""
    tree = ast.parse(SUITE_PATH.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "suite.py must not use relative imports"
            assert node.module is not None
            modules.add(node.module)
    return modules


def test_suite_imports_only_contract_and_models() -> None:
    modules = _suite_imported_modules()
    assert "app.storage.contract" in modules, "the suite must talk to the contract"
    for module in modules:
        allowed = module in SUITE_ALLOWED_IMPORTS or module.startswith(
            SUITE_ALLOWED_IMPORT_PREFIXES
        )
        assert allowed, f"suite.py must not import {module!r}"
        banned = [token for token in BANNED_IMPORT_SUBSTRINGS if token in module]
        assert not banned, f"suite.py must not import {module!r} ({banned})"


def test_importing_the_suite_loads_no_driver_or_adapter() -> None:
    # Fresh-interpreter proof (Phase 01 task-6 / Phase 02 task-1 precedent):
    # importing the suite module cannot pull in sqlite3 or any adapter.
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env["PYTHONPATH"] = os.pathsep.join([str(SRC_ROOT), str(TESTS_ROOT)])
    probe = """
import sys
import storage_contract.suite
for leaked in (
    "sqlite3",
    "boto3",
    "botocore",
    "app.storage.sqlite",
    "app.storage.dynamodb",
):
    assert leaked not in sys.modules, leaked
print("clean")
"""
    result = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=SRC_ROOT.parent,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"subprocess suite import check failed: {result.stderr}"
    assert result.stdout.strip() == "clean"
