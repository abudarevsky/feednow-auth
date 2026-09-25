"""Subprocess acceptance for the Phase 13 task-5 administrator CLI on SQLite.

The unit suite (``test_admin_cli.py``) proves the CLI contract against a stub
storage; this module proves the **real** ``python -m feednow_auth.admin``
entry point end-to-end over a committed SQLite database on a temp file. Each
run is a genuine subprocess (its own interpreter, its own ``-m`` import of
``feednow_auth.admin``, its own environment), so the packaging shim, the
``if __name__ == "__main__"`` guard, the env→settings→storage factory
pipeline, and the task-3 service are all exercised for real — none of which a
same-process call can prove. Acceptance mapping (breakdown task 5 "Verify"):

- **real ``-m`` entry point** — every assertion runs the CLI as a subprocess
  with ``PYTHONPATH=src``; a broken shim or guard would fail on import;
- **role persistence** — ``grant`` flips the committed ``users.application_role``
  to ``admin`` and appends exactly one audit row (read back through a separate
  connection);
- **double-grant single audit** — a second ``grant`` exits 0 printing
  ``already granted`` and leaves the audit table at one row (idempotent
  no-op; no duplicate audit, spec 13 behavior 7);
- **exit 5 on the last admin** — revoking the only ACTIVE administrator exits
  5 and mutates nothing (the adapter guard, surfaced through the CLI).
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from app.models.enums import (
    ApplicationRole,
    MembershipRole,
    MembershipStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.ids import MembershipId, OrganizationId, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.services.administration import GRANT_ACTION
from app.storage.sqlite import open_sqlite_storage

_SRC = Path(__file__).resolve().parents[2]
_SEED_T0 = datetime(2026, 9, 20, 8, 0, 0, tzinfo=UTC)
_EMAIL = "bootstrap@example.test"


def _seed(
    db_path: Path,
    user_id: str,
    *,
    email: str = _EMAIL,
    application_role: ApplicationRole = ApplicationRole.USER,
) -> None:
    """Seed one user + its active-organization audit anchor, then release the file.

    Opens the real adapter (running migrations), writes the committed truth,
    and closes so the subprocess sees an unlocked database.
    """
    storage = open_sqlite_storage(db_path)
    try:
        storage.create_user(
            User(
                id=UserId(user_id),
                display_name=f"operator {user_id}",
                email=email,
                status=UserStatus.ACTIVE,
                application_role=application_role,
                created_at=_SEED_T0,
                updated_at=_SEED_T0,
            )
        )
        storage.create_organization(
            Organization(
                id=OrganizationId("org_anchor"),
                name="Anchor Org",
                slug="org-anchor",
                type=OrganizationType.CUSTOMER,
                status=OrganizationStatus.ACTIVE,
                created_at=_SEED_T0,
                updated_at=_SEED_T0,
            )
        )
        storage.create_membership(
            Membership(
                id=MembershipId(f"mem_{user_id.removeprefix('usr_')}_anchor"),
                organization_id=OrganizationId("org_anchor"),
                user_id=UserId(user_id),
                role=MembershipRole.OWNER,
                status=MembershipStatus.ACTIVE,
                created_at=_SEED_T0,
            )
        )
    finally:
        storage.close()


def _run_cli(db_path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Invoke ``python -m feednow_auth.admin`` as a real subprocess."""
    environ = dict(os.environ)
    environ["PYTHONPATH"] = str(_SRC)
    environ["FEEDNOW_STORAGE_BACKEND"] = "sqlite"
    environ["FEEDNOW_SQLITE_PATH"] = str(db_path)
    return subprocess.run(
        [sys.executable, "-m", "feednow_auth.admin", *args],
        capture_output=True,
        text=True,
        env=environ,
        cwd=str(_SRC.parent),
        timeout=120,
        check=False,
    )


def _role_of(db_path: Path, user_id: str) -> str:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT application_role FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()
    assert row is not None
    return str(row[0])


def _audit_rows(db_path: Path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return list(conn.execute("SELECT * FROM audit_events ORDER BY rowid"))
    finally:
        conn.close()


def test_grant_persists_role_and_one_audit_through_the_m_entry_point(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "admin_cli.sqlite"
    _seed(db_path, "usr_cli_grant")

    result = _run_cli(db_path, "grant", "--email", _EMAIL)

    assert result.returncode == 0, result.stderr
    assert result.stdout == f"granted {_EMAIL}\n"
    assert _role_of(db_path, "usr_cli_grant") == "admin"
    audits = _audit_rows(db_path)
    assert len(audits) == 1
    assert audits[0]["action"] == GRANT_ACTION
    assert audits[0]["target_id"] == "usr_cli_grant"


def test_double_grant_is_idempotent_with_a_single_audit(tmp_path: Path) -> None:
    db_path = tmp_path / "admin_cli_double.sqlite"
    _seed(db_path, "usr_cli_double")

    first = _run_cli(db_path, "grant", "--email", _EMAIL)
    second = _run_cli(db_path, "grant", "--email", _EMAIL)

    assert first.returncode == 0, first.stderr
    assert first.stdout == f"granted {_EMAIL}\n"
    assert second.returncode == 0, second.stderr
    assert second.stdout == f"already granted {_EMAIL}\n"
    # The no-op wrote no second audit row (spec 13 behavior 7).
    assert len(_audit_rows(db_path)) == 1
    assert _role_of(db_path, "usr_cli_double") == "admin"


def test_revoke_last_active_admin_exits_five_and_mutates_nothing(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "admin_cli_last.sqlite"
    _seed(db_path, "usr_cli_last", application_role=ApplicationRole.ADMIN)

    result = _run_cli(db_path, "revoke", "--email", _EMAIL)

    assert result.returncode == 5
    assert "last active administrator" in result.stderr
    assert result.stdout == ""
    # Refusal is fully rolled back: still admin, and no audit was written.
    assert _role_of(db_path, "usr_cli_last") == "admin"
    assert _audit_rows(db_path) == []


def test_missing_user_exits_three_through_the_m_entry_point(tmp_path: Path) -> None:
    db_path = tmp_path / "admin_cli_missing.sqlite"
    # Seed a different user so the database exists and is migrated.
    _seed(db_path, "usr_cli_other", email="someone-else@example.test")

    result = _run_cli(db_path, "grant", "--email", _EMAIL)

    assert result.returncode == 3
    assert _EMAIL in result.stderr
    assert "Traceback" not in result.stderr


def test_usage_error_exits_two_without_touching_the_database(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "admin_cli_usage.sqlite"
    _seed(db_path, "usr_cli_usage")

    result = _run_cli(db_path, "grant")  # missing --email

    assert result.returncode == 2
    assert "usage" in result.stderr
    # No mutation: the seeded user is untouched and no audit exists.
    assert _role_of(db_path, "usr_cli_usage") == "user"
    assert _audit_rows(db_path) == []
