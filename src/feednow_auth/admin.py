"""Application-administrator bootstrap CLI (Phase 13 task 5).

The only administration interface spec 13 authorizes is this operator CLI:

.. code-block:: bash

    python -m feednow_auth.admin grant --email admin@example.com
    python -m feednow_auth.admin revoke --email admin@example.com

There is no HTTP bootstrap endpoint, no default admin credential, and no
environment-driven or startup-time promotion — this module is invoked by an
operator, never by deployment or container startup (spec 13 required
behaviors 1-4).

Import contract (required behavior 4, pinned by the breakdown): importing
this module performs **no I/O and no credential lookup**. Environment is read
only inside :func:`main`, through the pipeline
``storage_settings_from_env(os.environ)`` → ``create_storage`` →
:mod:`app.services.administration`. The module-level code is declarations
only (argparse wiring, constants, function definitions, and the ``__main__``
guard), which the unit tests prove by AST.

Pinned CLI exit/error contract (the exit codes are stable operator-facing
API; the task-8 runbook documents this table):

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
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from collections.abc import Sequence

from app.services.administration import (
    AdministratorNotFoundError,
    AmbiguousAdministratorEmailError,
    grant_administrator,
    revoke_administrator,
)
from app.storage.contract import (
    LastActiveAdministratorError,
    RoleTransitionOutcome,
    Storage,
)
from app.storage.factory import create_storage, storage_settings_from_env

#: Pinned CLI exit codes (see the module docstring table).
EXIT_SUCCESS = 0
EXIT_UNEXPECTED = 1
EXIT_USAGE = 2
EXIT_NO_USER = 3
EXIT_AMBIGUOUS_EMAIL = 4
EXIT_LAST_ACTIVE_ADMIN = 5

#: Fixed, safe line for every unexpected failure: no traceback, no exception
#: text (adapter messages stay inside the process).
_UNEXPECTED_FAILURE = "error: administrator command failed"

_GRANT = "grant"
_REVOKE = "revoke"
_LIST = "list"


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
        dest="command", required=True, metavar="{grant,revoke,list}"
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
    return parser


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
    print("id\temail\tstatus\trole\tregistered_at\tlast_login")
    for user in users:
        registered = user.created_at.isoformat().replace("+00:00", "Z")
        print(
            f"{user.id}\t{user.email}\t{user.status}\t{user.application_role}"
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
    settings, ``create_storage`` opens the named adapter, and the task-3
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
        return _run_command(storage, command=args.command, email=args.email)
    finally:
        _close_quietly(storage)


if __name__ == "__main__":
    raise SystemExit(main())
