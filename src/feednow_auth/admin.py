"""Application-administrator bootstrap CLI (admin).

The only administration interface contract 13 authorizes is this operator CLI:

.. code-block:: bash

    python -m feednow_auth.admin grant --email admin@example.com
    python -m feednow_auth.admin revoke --email admin@example.com

There is no HTTP bootstrap endpoint, no default admin credential, and no
environment-driven or startup-time promotion — this module is invoked by an
operator, never by deployment or container startup (contract 13 required
behaviors 1-4).

Import contract (required behavior 4, pinned by the design notes): importing
this module performs **no I/O and no credential lookup**. Environment is read
only inside :func:`main`, through the pipeline
``storage_settings_from_env(os.environ)`` → ``create_storage`` →
:mod:`app.services.administration`. The module-level code is declarations
only (argparse wiring, constants, function definitions, and the ``__main__``
guard), which the unit tests prove by AST.

Pinned CLI exit/error contract (the exit codes are stable operator-facing
API; the implementation runbook documents this table):

=====  ==========================================================
code   meaning
=====  ==========================================================
0      success — stdout distinguishes ``granted`` /
       ``already granted`` / ``revoked`` / ``already revoked``
       (idempotent no-ops exit 0 and write no duplicate audit)
2      usage error (argparse: missing/unknown subcommand, missing
       ``--email``) **or** unusable storage configuration
       (``ValueError`` from the env-derived factory settings — the
       factory's rejection messages are fixed and value-free, so
       echoing one is log-safe)
3      no user exists for that email
4      ambiguous email — stderr lists the candidate ``usr_`` ids
5      refused: the revoke would remove the last active administrator
1      any unexpected failure (``StorageError`` or anything else) —
       one fixed safe stderr line, never a traceback
=====  ==========================================================

Message policy: echoing the operator-supplied email and the ``usr_`` ids is
allowed (the operator already holds the email; ids are internal identities,
not secrets). No token, credential, or provider material is ever printed,
and unexpected failures print only the fixed line — the underlying exception
text (adapter detail) never reaches stderr.

Current behavior and invariants: ``docs/architecture.md``."""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from collections.abc import Sequence
from typing import cast

from app.models.ids import OrganizationId
from app.services.administration import (
    AdministratorNotFoundError,
    AmbiguousAdministratorEmailError,
    grant_administrator,
    revoke_administrator,
)
from app.services.organization_onboarding import dispatch_organization_onboarding
from app.storage.contract import (
    LastActiveAdministratorError,
    RoleTransitionOutcome,
    Storage,
)
from app.storage.factory import create_storage, storage_settings_from_env
from app.storage.local_admin import LocalAdminStorage
from feednow_auth.demo_organizations import (
    DemoProvisioningError,
    create_demo_organization,
    delete_demo_organization,
    list_demo_organizations,
    reset_demo_password,
)

#: Pinned CLI exit codes (see the module docstring table).
EXIT_SUCCESS = 0
EXIT_UNEXPECTED = 1
EXIT_USAGE = 2
EXIT_NO_USER = 3
EXIT_AMBIGUOUS_EMAIL = 4
EXIT_LAST_ACTIVE_ADMIN = 5
EXIT_NO_ONBOARDING_REQUEST = 6

#: Fixed, safe line for every unexpected failure: no traceback, no exception
#: text (adapter messages stay inside the process).
_UNEXPECTED_FAILURE = "error: administrator command failed"

_GRANT = "grant"
_REVOKE = "revoke"
_LIST = "list"
_ONBOARDING_STATUS = "onboarding-status"
_ONBOARDING_RETRY = "onboarding-retry"
_DEMO = "demo"
_DEMO_CREATE = "create"
_DEMO_DELETE = "delete"
_DEMO_LIST = "list"
_DEMO_RESET_PASSWORD = "reset-password"


def _build_parser() -> argparse.ArgumentParser:
    """Construct the argparse tree: ``grant``/``revoke`` with ``--email``.

    A missing or unknown subcommand and a missing ``--email`` are argparse
    usage errors, which exit with code 2 — exactly the pinned contract.
    """
    parser = argparse.ArgumentParser(
        prog="feednow-admin",
        description="Manage FeedNow application administrator roles.",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="{grant,revoke,list,onboarding-status,onboarding-retry,demo}",
    )
    grant = subparsers.add_parser(_GRANT, help="promote the user for --email to admin")
    revoke = subparsers.add_parser(_REVOKE, help="demote the user for --email to user")
    for command in (grant, revoke):
        command.add_argument(
            "--email",
            required=True,
            metavar="<addr>",
            help="exact email address of the (already registered) user",
        )
    subparsers.add_parser(
        _LIST, help="list users, roles, registration date, and login availability"
    )
    for command in (_ONBOARDING_STATUS, _ONBOARDING_RETRY):
        subparsers.add_parser(command).add_argument(
            "--organization-id", required=True, metavar="<org_id>"
        )
    demo = subparsers.add_parser(_DEMO, help="manage demo organizations and their Cognito login")
    demo_commands = demo.add_subparsers(dest="demo_command", required=True)
    create = demo_commands.add_parser(_DEMO_CREATE, help="create a demo organization and login")
    create.add_argument("--name", required=True, metavar="<name>")
    create.add_argument(
        "--slug",
        metavar="<slug>",
        help=(
            "FeedNow organization slug (defaults to normalized name); email-sign-in "
            "pools use <slug>@demo.feednow.io"
        ),
    )
    delete = demo_commands.add_parser(_DEMO_DELETE, help="delete a demo organization and its login")
    delete.add_argument("--org", required=True, metavar="<slug>")
    reset_password = demo_commands.add_parser(
        _DEMO_RESET_PASSWORD, help="generate and set a new demo login password"
    )
    reset_password.add_argument("--org", required=True, metavar="<slug>")
    demo_commands.add_parser(_DEMO_LIST, help="list demo organizations without credentials")
    return parser


def _run_demo(storage: Storage, *, command: str, args: argparse.Namespace) -> int:
    managed_storage = cast(LocalAdminStorage, storage)
    try:
        if command == _DEMO_CREATE:
            organization, login_identifier, password = create_demo_organization(
                managed_storage, name=args.name, slug=args.slug
            )
            onboarding = "pending; use onboarding-retry if dispatch is not configured"
            base_url = os.environ.get("FEEDNOW_VISPECTOR_URL", "").strip()
            credential = os.environ.get("FEEDNOW_VISPECTOR_SERVICE_SECRET", "")
            if base_url and credential:
                try:
                    delivered = dispatch_organization_onboarding(
                        managed_storage,
                        organization.id,
                        base_url=base_url,
                        service_credential=credential,
                    )
                    onboarding = (
                        "succeeded" if delivered else "pending; retry with onboarding-retry"
                    )
                except Exception:
                    onboarding = "pending; retry with onboarding-retry"
            print(
                "Demo organization created\n\n"
                f"Organization: {organization.name}\n"
                f"Organization ID: {organization.id}\n"
                f"Organization slug: {organization.slug}\n"
                f"Vispector onboarding: {onboarding}\n"
                f"Login: {login_identifier}\n"
                f"Password: {password}\n\n"
                "Store the password now. It cannot be retrieved later."
            )
            return EXIT_SUCCESS
        if command == _DEMO_DELETE:
            delete_demo_organization(managed_storage, slug=args.org)
            print(f"deleted demo organization {args.org}")
            return EXIT_SUCCESS
        if command == _DEMO_RESET_PASSWORD:
            login_identifier, password = reset_demo_password(managed_storage, slug=args.org)
            print(
                "Demo password reset\n\n"
                f"Login: {login_identifier}\n"
                f"Password: {password}\n\n"
                "Store the password now. It cannot be retrieved later."
            )
            return EXIT_SUCCESS
        print("NAME\tLOGIN\tSTATUS")
        for name, username, status in list_demo_organizations(managed_storage):
            print(f"{name}\t{username}\t{status}")
        return EXIT_SUCCESS
    except DemoProvisioningError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_UNEXPECTED
    except Exception:
        print(_UNEXPECTED_FAILURE, file=sys.stderr)
        return EXIT_UNEXPECTED


def _run_onboarding(storage: Storage, *, command: str, organization_id: str) -> int:
    """Inspect or retry one secret-free durable organization onboarding record."""
    try:
        org_id = OrganizationId(organization_id)
        request = storage.get_organization_onboarding_request(org_id)
        if request is None:
            print("error: no onboarding request exists for organization", file=sys.stderr)
            return EXIT_NO_ONBOARDING_REQUEST
        if command == _ONBOARDING_RETRY:
            base_url = os.environ.get("FEEDNOW_VISPECTOR_URL", "").strip()
            credential = os.environ.get("FEEDNOW_VISPECTOR_SERVICE_SECRET", "")
            if not base_url or not credential:
                print("error: onboarding retry configuration is missing", file=sys.stderr)
                return EXIT_USAGE
            dispatch_organization_onboarding(
                storage,
                org_id,
                base_url=base_url,
                service_credential=credential,
            )
            request = storage.get_organization_onboarding_request(org_id)
            if request is None:
                raise RuntimeError("onboarding record disappeared")
        print(
            f"organization_id\t{request.organization_id}\n"
            f"request_id\t{request.request_id}\n"
            f"bootstrap_version\t{request.bootstrap_version}\n"
            f"status\t{request.status}\n"
            f"attempts\t{request.attempts}\n"
            f"updated_at\t{request.updated_at.isoformat()}\n"
            f"last_error\t{request.last_error or 'none'}"
        )
        return (
            EXIT_SUCCESS
            if request.status == "succeeded" or command == _ONBOARDING_STATUS
            else EXIT_UNEXPECTED
        )
    except Exception:
        print(_UNEXPECTED_FAILURE, file=sys.stderr)
        return EXIT_UNEXPECTED


def _system_exit_code(exc: SystemExit) -> int:
    """Translate argparse's SystemExit into the pinned return codes."""
    if isinstance(exc.code, int):
        return exc.code
    return EXIT_SUCCESS if exc.code is None else EXIT_UNEXPECTED


def _run_command(storage: Storage, *, command: str, email: str) -> int:
    """Execute one grant/revoke command; the return value is the exit code.

    The service owns every decision (resolution, anchor, audit formation, the
    atomic transition); this function only maps the typed refusals to the
    pinned exit codes and the adapter outcome to the stdout wording. Catch
    order matters: :class:`LastActiveAdministratorError` is a ``StorageError``
    and must be translated to 5 before any generic failure handler sees it.
    """
    try:
        if command == _GRANT:
            transition = grant_administrator(storage, email)
            changed, unchanged = "granted", "already granted"
        else:
            transition = revoke_administrator(storage, email)
            changed, unchanged = "revoked", "already revoked"
    except AdministratorNotFoundError:
        print(f"error: no user exists for email {email}", file=sys.stderr)
        return EXIT_NO_USER
    except AmbiguousAdministratorEmailError as exc:
        print(
            f"error: email {email} matches {exc.count} users; refusing",
            file=sys.stderr,
        )
        for user_id in exc.user_ids:
            print(f"  {user_id}", file=sys.stderr)
        return EXIT_AMBIGUOUS_EMAIL
    except LastActiveAdministratorError:
        print("error: refusing to revoke the last active administrator", file=sys.stderr)
        return EXIT_LAST_ACTIVE_ADMIN
    except Exception:
        print(_UNEXPECTED_FAILURE, file=sys.stderr)
        return EXIT_UNEXPECTED
    outcome = changed if transition.outcome is RoleTransitionOutcome.TRANSITIONED else unchanged
    print(f"{outcome} {email}")
    return EXIT_SUCCESS


def _run_list(storage: Storage) -> int:
    """Print operator-visible account metadata; login time is not persisted."""
    try:
        users = storage.list_users()
    except Exception:
        print(_UNEXPECTED_FAILURE, file=sys.stderr)
        return EXIT_UNEXPECTED
    print("id\tusername\temail\tstatus\trole\tregistered_at\tlast_login")
    for user in users:
        registered = user.created_at.isoformat().replace("+00:00", "Z")
        print(
            f"{user.id}\t{user.username or ''}\t{user.email or ''}\t{user.status}"
            f"\t{user.application_role}"
            f"\t{registered}\tnot recorded"
        )
    return EXIT_SUCCESS


def _close_quietly(storage: Storage | None) -> None:
    """Best-effort adapter release; ``close`` is not on the ``Storage`` protocol.

    SQLite/DynamoDB adapters expose it, stubs in tests need not. A release
    failure must never turn a decided exit code into a traceback, so it is
    suppressed by construction.
    """
    if storage is None:
        return
    close = getattr(storage, "close", None)
    if not callable(close):
        return
    with contextlib.suppress(Exception):
        close()


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``python -m feednow_auth.admin``; returns the exit code.

    The process environment is read **here and only here** (module import
    performs no I/O): ``storage_settings_from_env(os.environ)`` derives the
    settings, ``create_storage`` opens the named adapter, and the implementation
    administration service does the work over the ``Storage`` contract.
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # usage (2) / --help (0), never a raise past -m
        return _system_exit_code(exc)
    try:
        settings = storage_settings_from_env(os.environ)
    except ValueError as exc:
        # Fixed, value-free factory message: misconfiguration is a usage error.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    storage: Storage | None = None
    try:
        try:
            storage = create_storage(settings)
        except Exception:
            print(_UNEXPECTED_FAILURE, file=sys.stderr)
            return EXIT_UNEXPECTED
        if args.command == _LIST:
            return _run_list(storage)
        if args.command == _DEMO:
            return _run_demo(storage, command=args.demo_command, args=args)
        if args.command in {_ONBOARDING_STATUS, _ONBOARDING_RETRY}:
            return _run_onboarding(
                storage, command=args.command, organization_id=args.organization_id
            )
        return _run_command(storage, command=args.command, email=args.email)
    finally:
        _close_quietly(storage)


if __name__ == "__main__":
    raise SystemExit(main())
