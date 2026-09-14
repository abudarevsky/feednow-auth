"""Phase 06 acceptance proofs: the DynamoDB boundary holds repo-wide (task 9).

AC 1 of the phase spec: "No service/API module imports DynamoDB client types
or catches DynamoDB exceptions." The per-file subprocess proofs from Phases
01/02 (``test_app_skeleton.py``, ``test_storage_contract.py``) pin the two
known import roots; this file adds the **repo-wide AST scan** promised by
breakdown decision 7: every ``.py`` under ``src/app`` except
``storage/dynamodb.py`` itself is parsed and may not import ``boto3``,
``botocore`` (any submodule), or the adapter module
``app.storage.dynamodb`` (absolute *or* relative form, resolved to dotted
names so ``from . import dynamodb`` inside ``app/storage`` cannot smuggle
it past a substring check). Catching a driver exception requires importing
it, so the import ban covers AC 1's "catches" clause structurally.

The positive-control test proves the scan is not vacuous: the adapter module
is the **only** file under ``src/app`` whose imports mention the drivers.
The final test re-runs the established subprocess-isolated proof for the
whole app entrypoint (fresh interpreter, so test order can never skew the
result) with the Phase 06 module names added to the leak list.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[3]
SRC_ROOT: Path = REPO_ROOT / "src"
SRC_APP: Path = SRC_ROOT / "app"

#: The adapter module is the one place DynamoDB-specific code may live.
ADAPTER_PATH: Path = SRC_APP / "storage" / "dynamodb.py"

#: Driver package roots banned everywhere else under ``src/app``.
BANNED_ROOTS: frozenset[str] = frozenset({"boto3", "botocore"})

#: The adapter module name banned everywhere else under ``src/app``.
BANNED_MODULE: str = "app.storage.dynamodb"


def _app_files() -> list[Path]:
    """Every runtime module under ``src/app`` (sorted, deterministic)."""
    return sorted(SRC_APP.rglob("*.py"))


def _owning_package(path: Path) -> str:
    """The dotted package that owns ``path`` (its directory, for the app)."""
    parts = list(path.relative_to(SRC_ROOT).parts)
    return ".".join(parts[:-1])


def _resolved_imports(path: Path) -> set[str]:
    """Absolute dotted names every import statement in ``path`` can load.

    ``ast.Import`` contributes its names directly; ``ast.ImportFrom``
    contributes both the module and ``<module>.<alias>`` (so
    ``from app.storage import dynamodb`` yields ``app.storage.dynamodb``),
    with relative levels resolved against the file's owning package.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package = _owning_package(path)
    targets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                base = node.module or ""
            else:
                parts = package.split(".") if package else []
                keep = len(parts) - (node.level - 1)
                base = ".".join(parts[:keep])
                if node.module:
                    base = f"{base}.{node.module}" if base else node.module
            for alias in node.names:
                targets.add(f"{base}.{alias.name}" if base else alias.name)
    return targets


def _banned_targets(targets: set[str]) -> set[str]:
    """The subset of resolved import names that AC 1 bans outside the adapter."""
    banned: set[str] = set()
    for target in targets:
        root = target.split(".")[0]
        if (
            root in BANNED_ROOTS
            or target == BANNED_MODULE
            or target.startswith(f"{BANNED_MODULE}.")
        ):
            banned.add(target)
    return banned


def _driver_importers() -> list[Path]:
    """Every ``src/app`` module importing a banned root (adapter included)."""
    return [
        path
        for path in _app_files()
        if any(target.split(".")[0] in BANNED_ROOTS for target in _resolved_imports(path))
    ]


# ---------------------------------------------------------------------------
# AC 1: the AST boundary scan (repo-wide, no server needed)
# ---------------------------------------------------------------------------


def test_the_runtime_tree_was_scanned_and_includes_the_adapter() -> None:
    # Sanity gate so the boundary tests below can never pass vacuously on an
    # empty or mislocated scan root.
    files = _app_files()
    assert len(files) >= 30, files
    assert ADAPTER_PATH in files
    assert SRC_APP / "storage" / "contract.py" in files
    assert SRC_APP / "main.py" in files


def test_no_app_module_outside_the_adapter_touches_dynamo_or_the_adapter() -> None:
    offenders: list[str] = []
    for path in _app_files():
        if path == ADAPTER_PATH:
            continue
        banned = _banned_targets(_resolved_imports(path))
        offenders.extend(f"{path.relative_to(REPO_ROOT)}: {name}" for name in sorted(banned))
    assert offenders == [], "AC 1 violated (DynamoDB import above the adapter): " + "; ".join(
        offenders
    )


def test_the_adapter_is_the_only_driver_importer() -> None:
    # Positive control: the banned names genuinely exist in the scanned
    # namespace, and exactly one module owns them — the scan proves a
    # boundary, not an absence of code.
    assert _driver_importers() == [ADAPTER_PATH]
    adapter_targets = _resolved_imports(ADAPTER_PATH)
    assert "boto3" in adapter_targets
    assert any(target.split(".")[0] == "botocore" for target in adapter_targets)


def test_storage_package_init_imports_the_contract_only() -> None:
    # ``app/storage/__init__.py`` must stay adapter-free (its docstring
    # mandates it): every import it resolves must be the contract module.
    targets = _resolved_imports(SRC_APP / "storage" / "__init__.py")
    assert targets, "the storage package must import the contract"
    for target in targets:
        assert target == "app.storage.contract" or target.startswith("app.storage.contract."), (
            target
        )


# ---------------------------------------------------------------------------
# Runtime counterpart: fresh-interpreter proof for the app entrypoint
# ---------------------------------------------------------------------------


def test_importing_app_main_loads_no_dynamo_driver_or_adapter() -> None:
    # Subprocess-isolated (the Phase 01/02 precedent): a fresh interpreter,
    # AWS config stripped, so test order can never skew the result. The
    # Phase 06 leak list adds ``botocore`` and the adapter module itself to
    # the ``boto3`` proof already pinned in ``test_app_skeleton.py``.
    env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
    env["PYTHONPATH"] = str(SRC_ROOT)
    probe = """
import sys
import app.main
for leaked in (
    "boto3",
    "botocore",
    "app.storage.dynamodb",
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
