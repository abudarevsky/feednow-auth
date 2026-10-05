"""Unit proofs for the admin implementation administrator CLI (``feednow_auth.admin``).

The stub suite proves the *CLI contract* without a database: argparse wiring,
the pinned exit-code table (0/2/3/4/5/1), the stdout wording that
distinguishes ``granted`` / ``already granted`` / ``revoked`` / ``already
revoked``, the stderr rules (ambiguous lists the ``usr_`` ids; unexpected
failures print exactly one fixed safe line with no traceback and no
exception-text leak), and the import purity required by contract 13 behavior 4
(no I/O, no credential lookup, no environment read at import time).

Storage is injected by monkeypatching the module-level ``create_storage``
seam while the **real** ``storage_settings_from_env`` runs against an
injected environment (``monkeypatch.setenv``), so the env→settings→storage
pipeline itself is exercised. Real subprocess ``-m`` execution against
committed SQLite truth is owned by
``src/tests/integration/test_admin_cli_sqlite.py``.

Current behavior and invariants: ``docs/administration.md``."""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

import feednow_auth.admin as admin
from app.models.enums import ApplicationRole, OrganizationStatus, OrganizationType
from app.models.ids import OrganizationId, UserId
from app.models.organization import Organization
from app.models.organization_onboarding import OrganizationOnboardingRequest
from app.models.pagination import Page, PageParams
from app.models.user import User
from app.services.administration import AdministratorAuditAnchorMissingError
from app.storage.contract import (
    LastActiveAdministratorError,
    RoleTransition,
    RoleTransitionOutcome,
    StorageError,
)
from app.storage.factory import SqliteStorageSettings

_NOW = datetime(2026, 9, 25, 10, 0, 0, tzinfo=UTC)
_EMAIL = "admin@example.test"


def _user(
    user_id: str,
    *,
    email: str = _EMAIL,
    application_role: ApplicationRole = ApplicationRole.USER,
) -> User:
    return User(
        id=UserId(user_id),
        display_name=f"operator {user_id}",
        email=email,
        status="active",
        application_role=application_role,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _organization(organization_id: str = "org_anchor") -> Organization:
    return Organization(
        id=OrganizationId(organization_id),
        name="Anchor Org",
        slug=f"org-{organization_id}",
        type=OrganizationType.CUSTOMER,
        status=OrganizationStatus.ACTIVE,
        created_at=_NOW,
        updated_at=_NOW,
    )


class StubStorage:
    """``Storage`` stub implementing exactly the surface the CLI pipeline touches.

    ``transition_application_role`` replays the adapter contract: scripted
    outcome (``TRANSITIONED``/``NO_CHANGE``) or scripted error. ``closed``
    counts ``close()`` calls so the CLI's best-effort release is observable.
    """

    def __init__(
        self,
        users: list[User],
        *,
        organizations: list[Organization] | None = None,
        outcome: RoleTransitionOutcome = RoleTransitionOutcome.TRANSITIONED,
        error: Exception | None = None,
    ) -> None:
        self.users = users
        self.organizations = list(organizations if organizations is not None else [_organization()])
        self.outcome = outcome
        self.error = error
        self.transition_calls = 0
        self.closed = 0
        self.onboarding_request: OrganizationOnboardingRequest | None = None

    def get_organization_onboarding_request(self, organization_id: OrganizationId):
        if self.onboarding_request is None:
            return None
        if self.onboarding_request.organization_id != organization_id:
            return None
        return self.onboarding_request

    def update_organization_onboarding_request(
        self, request: OrganizationOnboardingRequest
    ) -> None:
        self.onboarding_request = request

    def list_users_by_email(self, email: str) -> list[User]:
        return [user for user in self.users if user.email == email]

    def list_users(self) -> list[User]:
        return sorted(self.users, key=lambda user: (user.created_at, str(user.id)))

    def list_user_organizations(self, user_id: UserId, page: PageParams) -> Page[Organization]:
        return Page(items=self.organizations[: page.limit], limit=page.limit, next_cursor=None)

    def transition_application_role(
        self,
        *,
        user_id: UserId,
        expected_role: ApplicationRole,
        new_role: ApplicationRole,
        updated_at: datetime,
        audit_event: Any,
    ) -> RoleTransition:
        self.transition_calls += 1
        if self.error is not None:
            raise self.error
        stored = next(user for user in self.users if user.id == user_id)
        if self.outcome is RoleTransitionOutcome.NO_CHANGE:
            return RoleTransition(user=stored, outcome=RoleTransitionOutcome.NO_CHANGE)
        updated = stored.model_copy(update={"application_role": new_role, "updated_at": updated_at})
        return RoleTransition(user=updated, outcome=RoleTransitionOutcome.TRANSITIONED)

    def close(self) -> None:
        self.closed += 1


@pytest.fixture
def sqlite_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> str:
    """Inject a valid sqlite backend environment; return the (never opened) path."""
    path = str(tmp_path / "cli-unused.db")
    monkeypatch.setenv("FEEDNOW_STORAGE_BACKEND", "sqlite")
    monkeypatch.setenv("FEEDNOW_SQLITE_PATH", path)
    return path


def _install(monkeypatch: pytest.MonkeyPatch, storage: StubStorage) -> list[object]:
    """Swap the module-level ``create_storage`` seam; record the settings passed."""
    seen: list[object] = []

    def fake_create(settings: object) -> StubStorage:
        seen.append(settings)
        return storage

    monkeypatch.setattr(admin, "create_storage", fake_create)
    return seen


# ---------------------------------------------------------------------------
# Pinned exit-code table
# ---------------------------------------------------------------------------


def test_exit_code_constants_are_pinned() -> None:
    assert admin.EXIT_SUCCESS == 0
    assert admin.EXIT_UNEXPECTED == 1
    assert admin.EXIT_USAGE == 2
    assert admin.EXIT_NO_USER == 3
    assert admin.EXIT_AMBIGUOUS_EMAIL == 4
    assert admin.EXIT_LAST_ACTIVE_ADMIN == 5


# ---------------------------------------------------------------------------
# Import purity (spec 13 behavior 4): no I/O, no env read, no credential lookup
# ---------------------------------------------------------------------------


def test_module_top_level_is_declaration_only() -> None:
    source_path = Path(admin.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    body = list(tree.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body.pop(0)  # module docstring
    guards = 0
    for index, node in enumerate(body):
        if isinstance(node, ast.If):
            # Only the ``if __name__ == "__main__"`` guard, and only last.
            test = node.test
            assert isinstance(test, ast.Compare)
            assert isinstance(test.left, ast.Name) and test.left.id == "__name__"
            assert index == len(body) - 1
            assert len(node.body) == 1 and isinstance(node.body[0], ast.Raise)
            guards += 1
            continue
        if isinstance(node, ast.Assign):
            # Constant-only module bindings (exit codes, fixed messages).
            assert all(isinstance(target, ast.Name) for target in node.targets)
            assert isinstance(node.value, ast.Constant)
            continue
        if isinstance(node, ast.AnnAssign):
            assert isinstance(node.target, ast.Name)
            assert node.value is None or isinstance(node.value, ast.Constant)
            continue
        assert isinstance(
            node,
            ast.Import | ast.ImportFrom | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
        ), f"unexpected executable top-level statement: {ast.dump(node)}"
    assert guards == 1, "the -m entry guard must exist exactly once"


def test_module_import_reads_no_environment_or_credentials() -> None:
    # A sanitized environment (no FEEDNOW_*/AWS_* at all) must not break the
    # import: env and credentials are only consulted inside main().
    src_root = Path(__file__).resolve().parents[2]
    environ = {
        key: value for key, value in os.environ.items() if not key.startswith(("FEEDNOW_", "AWS_"))
    }
    environ["PYTHONPATH"] = str(src_root)
    result = subprocess.run(
        [sys.executable, "-c", "import feednow_auth.admin"],
        capture_output=True,
        text=True,
        env=environ,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "Traceback" not in result.stderr


def test_package_init_is_empty_of_behavior() -> None:
    import feednow_auth

    tree = ast.parse(Path(feednow_auth.__file__).read_text(encoding="utf-8"))
    assert len(tree.body) == 1
    node = tree.body[0]
    assert isinstance(node, ast.Expr)
    assert isinstance(node.value, ast.Constant)
    assert isinstance(node.value.value, str)


# ---------------------------------------------------------------------------
# Usage errors (exit 2) — argparse owns these paths
# ---------------------------------------------------------------------------


def test_usage_no_subcommand_exits_two(sqlite_env: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert admin.main([]) == admin.EXIT_USAGE
    assert "usage" in capsys.readouterr().err


def test_usage_unknown_subcommand_exits_two(
    sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert admin.main(["promote", "--email", _EMAIL]) == admin.EXIT_USAGE
    assert "usage" in capsys.readouterr().err


def test_usage_missing_email_exits_two(sqlite_env: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert admin.main(["grant"]) == admin.EXIT_USAGE
    assert "--email" in capsys.readouterr().err


def test_help_exits_zero(sqlite_env: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert admin.main(["--help"]) == admin.EXIT_SUCCESS
    assert "usage" in capsys.readouterr().out


def test_onboarding_status_reports_only_safe_record_fields(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    storage = StubStorage([])
    storage.onboarding_request = OrganizationOnboardingRequest(
        request_id="onb_0123456789abcdef0123456789abcdef",
        organization_id="org_anchor",
        bootstrap_version="starter-v1",
        status="failed",
        attempts=3,
        created_at=_NOW,
        updated_at=_NOW,
        last_error="dispatch_unavailable",
    )
    _install(monkeypatch, storage)
    assert admin.main(["onboarding-status", "--organization-id", "org_anchor"]) == 0
    out = capsys.readouterr().out
    assert "status\tfailed" in out
    assert "attempts\t3" in out
    assert "secret" not in out


def test_onboarding_retry_uses_ephemeral_credential_and_updates_status(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    storage = StubStorage([])
    storage.onboarding_request = OrganizationOnboardingRequest(
        request_id="onb_0123456789abcdef0123456789abcdef",
        organization_id="org_anchor",
        bootstrap_version="starter-v1",
        status="failed",
        attempts=2,
        created_at=_NOW,
        updated_at=_NOW,
        last_error="dispatch_unavailable",
    )
    _install(monkeypatch, storage)
    monkeypatch.setenv("FEEDNOW_VISPECTOR_URL", "https://vispector.example")
    monkeypatch.setenv("FEEDNOW_VISPECTOR_SERVICE_SECRET", "temporary-secret")

    def dispatch(target, organization_id, *, base_url, service_credential):
        assert base_url == "https://vispector.example"
        assert service_credential == "temporary-secret"
        target.update_organization_onboarding_request(
            target.onboarding_request.model_copy(
                update={"status": "succeeded", "attempts": 3, "last_error": None}
            )
        )
        return True

    monkeypatch.setattr(admin, "dispatch_organization_onboarding", dispatch)
    assert admin.main(["onboarding-retry", "--organization-id", "org_anchor"]) == 0
    out = capsys.readouterr().out
    assert "status\tsucceeded" in out
    assert "temporary-secret" not in out


def test_missing_backend_configuration_exits_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # No FEEDNOW_STORAGE_BACKEND at all: the fixed, value-free factory reason
    # is printed and the CLI never reaches create_storage.
    monkeypatch.delenv("FEEDNOW_STORAGE_BACKEND", raising=False)
    monkeypatch.delenv("FEEDNOW_SQLITE_PATH", raising=False)
    monkeypatch.delenv("FEEDNOW_DYNAMODB_REGION", raising=False)
    monkeypatch.delenv("FEEDNOW_TABLE_PREFIX", raising=False)
    assert admin.main(["grant", "--email", _EMAIL]) == admin.EXIT_USAGE
    err = capsys.readouterr().err
    assert err.strip() == ("error: FEEDNOW_STORAGE_BACKEND must be exactly 'sqlite' or 'dynamodb'")
    assert "Traceback" not in err


# ---------------------------------------------------------------------------
# Success paths (exit 0) — stdout wording distinguishes all four outcomes
# ---------------------------------------------------------------------------


def test_grant_transitioned_prints_granted(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    storage = StubStorage([_user("usr_grant_target")])
    seen = _install(monkeypatch, storage)

    code = admin.main(["grant", "--email", _EMAIL])

    assert code == admin.EXIT_SUCCESS
    captured = capsys.readouterr()
    assert captured.out == f"granted {_EMAIL}\n"
    assert "already" not in captured.out
    assert captured.err == ""
    # The real env→settings pipeline ran and its settings reached the seam.
    assert seen == [SqliteStorageSettings(path=sqlite_env)]
    assert storage.transition_calls == 1
    assert storage.closed == 1  # best-effort adapter release


def test_grant_no_change_prints_already_granted(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    storage = StubStorage(
        [_user("usr_admin", application_role=ApplicationRole.ADMIN)],
        outcome=RoleTransitionOutcome.NO_CHANGE,
    )
    _install(monkeypatch, storage)

    code = admin.main(["grant", "--email", _EMAIL])

    assert code == admin.EXIT_SUCCESS
    captured = capsys.readouterr()
    assert captured.out == f"already granted {_EMAIL}\n"
    assert captured.err == ""


def test_revoke_transitioned_prints_revoked(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    # Revoke of an ADMIN is a real transition (the default scripted outcome).
    storage = StubStorage([_user("usr_revoke_target", application_role=ApplicationRole.ADMIN)])
    _install(monkeypatch, storage)

    code = admin.main(["revoke", "--email", _EMAIL])

    assert code == admin.EXIT_SUCCESS
    captured = capsys.readouterr()
    assert captured.out == f"revoked {_EMAIL}\n"
    assert captured.err == ""


def test_revoke_no_change_prints_already_revoked(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    storage = StubStorage([_user("usr_plain")], outcome=RoleTransitionOutcome.NO_CHANGE)
    _install(monkeypatch, storage)

    code = admin.main(["revoke", "--email", _EMAIL])

    assert code == admin.EXIT_SUCCESS
    captured = capsys.readouterr()
    assert captured.out == f"already revoked {_EMAIL}\n"
    assert captured.err == ""


# ---------------------------------------------------------------------------
# Resolution refusals (exit 3 / exit 4)
# ---------------------------------------------------------------------------


def test_no_user_exits_three(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    storage = StubStorage([_user("usr_other", email="someone-else@example.test")])
    _install(monkeypatch, storage)

    code = admin.main(["grant", "--email", _EMAIL])

    assert code == admin.EXIT_NO_USER
    captured = capsys.readouterr()
    assert captured.out == ""
    assert _EMAIL in captured.err  # echoing the operator-supplied email is allowed
    assert storage.transition_calls == 0
    assert "Traceback" not in captured.err


def test_ambiguous_email_exits_four_and_lists_usr_ids(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    storage = StubStorage([_user("usr_dup_one"), _user("usr_dup_two")])
    _install(monkeypatch, storage)

    code = admin.main(["grant", "--email", _EMAIL])

    assert code == admin.EXIT_AMBIGUOUS_EMAIL
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "usr_dup_one" in captured.err
    assert "usr_dup_two" in captured.err
    assert storage.transition_calls == 0


# ---------------------------------------------------------------------------
# Guard refusal (exit 5)
# ---------------------------------------------------------------------------


def test_last_active_admin_refusal_exits_five(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    storage = StubStorage(
        [_user("usr_last_admin", application_role=ApplicationRole.ADMIN)],
        error=LastActiveAdministratorError(),
    )
    _install(monkeypatch, storage)

    code = admin.main(["revoke", "--email", _EMAIL])

    assert code == admin.EXIT_LAST_ACTIVE_ADMIN
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "last active administrator" in captured.err
    assert "Traceback" not in captured.err


# ---------------------------------------------------------------------------
# Unexpected failures (exit 1) — one fixed line, no traceback, no leak
# ---------------------------------------------------------------------------


def test_unexpected_storage_error_exits_one_with_fixed_line(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    storage = StubStorage([_user("usr_boom")], error=StorageError("adapter-secret-detail"))
    _install(monkeypatch, storage)

    code = admin.main(["grant", "--email", _EMAIL])

    assert code == admin.EXIT_UNEXPECTED
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == admin._UNEXPECTED_FAILURE
    assert len(captured.err.strip().splitlines()) == 1
    assert "adapter-secret-detail" not in captured.err
    assert "Traceback" not in captured.err


def test_unexpected_generic_error_exits_one(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    storage = StubStorage([_user("usr_boom")], error=RuntimeError("boom-detail"))
    _install(monkeypatch, storage)

    code = admin.main(["grant", "--email", _EMAIL])

    assert code == admin.EXIT_UNEXPECTED
    captured = capsys.readouterr()
    assert captured.err.strip() == admin._UNEXPECTED_FAILURE
    assert "boom-detail" not in captured.err


def test_anchor_missing_refusal_exits_one(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    # No active organization: the service refuses before any transition.
    storage = StubStorage([_user("usr_no_org")], organizations=[])
    _install(monkeypatch, storage)

    code = admin.main(["grant", "--email", _EMAIL])

    assert code == admin.EXIT_UNEXPECTED
    captured = capsys.readouterr()
    assert captured.err.strip() == admin._UNEXPECTED_FAILURE
    assert storage.transition_calls == 0
    assert "Traceback" not in captured.err


def test_storage_open_failure_exits_one(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(settings: object) -> None:
        raise StorageError("cannot open adapter")

    monkeypatch.setattr(admin, "create_storage", boom)

    code = admin.main(["grant", "--email", _EMAIL])

    assert code == admin.EXIT_UNEXPECTED
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == admin._UNEXPECTED_FAILURE
    assert "cannot open adapter" not in captured.err


def test_list_prints_user_role_registration_and_unavailable_login(
    monkeypatch: pytest.MonkeyPatch, sqlite_env: str, capsys: pytest.CaptureFixture[str]
) -> None:
    storage = StubStorage(
        [
            _user("usr_list_user"),
            _user(
                "usr_list_admin",
                email="admin@example.test",
                application_role=ApplicationRole.ADMIN,
            ),
        ]
    )
    _install(monkeypatch, storage)

    code = admin.main(["list"])

    assert code == admin.EXIT_SUCCESS
    output = capsys.readouterr().out
    assert "id\temail\tstatus\trole\tregistered_at\tlast_login" in output
    assert "usr_list_user\tadmin@example.test\tactive\tuser\t" in output
    assert "usr_list_admin\tadmin@example.test\tactive\tadmin\t" in output
    assert output.count("not recorded") == 2


def test_anchor_error_class_is_not_special_cased() -> None:
    # Pin the mapping decision: the audit-anchor refusal is an "other failure"
    # (exit 1), not one of the pinned typed refusals (3/4/5).
    assert not issubclass(AdministratorAuditAnchorMissingError, StorageError)
