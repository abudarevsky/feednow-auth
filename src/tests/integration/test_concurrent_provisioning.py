"""Concurrent-first-login acceptance proof (Phase 03 task 6; spec §6).

The §6 race, exercised against the real SQLite adapter exactly as the
breakdown pins it:

- **8 threads on a ``threading.Barrier``** (no sleeps), same ``sub``,
  **distinct per-attempt IDs** — each attempt calls ``resolve_or_provision``
  without injected ``ids``, so every batch mints its own entropy and mirrors
  the real race where concurrent requests share the identity tuple but carry
  different ``usr_``/``org_``/``aud_`` ids; the verified profile email is
  **derived from the subject** (``_verified_email``), never a hardcoded
  placeholder, because §6 convergence is keyed on the identity tuple alone —
  proved by the distinct-per-attempt-email race below;
- one main-thread **read** before the barrier so first-connection and
  WAL-conversion PRAGMAs do not race inside the timed window; lock handling
  itself relies on the adapter's existing ``busy_timeout=5000`` +
  ``BEGIN IMMEDIATE`` discipline — nothing new is added here;
- outcome: exactly one user, identity, organization, owner membership, and
  three audit rows; **all threads resolve the same ``usr_``/``org_``** (the
  losers converge via decision 7's identity-tuple re-read, never a second
  ``provision_user``);
- final counts are asserted through **direct** fresh reads, and the race is
  repeated 20 times for stability.

Second case (sequential, not a race): two distinct ``sub``s deliberately
sharing one email — the collision *is* the subject under test here, so the
email is named explicitly (``_COLLISION_EMAIL``) instead of being derived.
The first provisions, the second gets
:class:`~app.services.identity.ProvisioningConflictError`, and the adapter's
rollback leaves **no partial rows**.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from app.auth.cognito import CognitoClaims, CognitoProfile
from app.models.enums import IdentityProvider
from app.models.user import User
from app.services.identity import (
    ProvisioningConflictError,
    ResolvedIdentity,
    resolve_or_provision,
)
from app.storage.contract import EntityNotFoundError
from app.storage.sqlite import open_sqlite_storage

_REPEATS = 20
_THREADS = 8
_SUB = "raced-sub-0123456789"

#: The email two *different* subjects collide on in the collision case. This
#: is the fixture under test, not a placeholder: the provisioning path takes
#: the batch email from the verified profile only, and the shared value is
#: what drives the ``users.email`` UNIQUE violation.
_COLLISION_EMAIL = "collision@example.test"

#: Domain of every derived verified email, so per-attempt variants can stay
#: well-formed addresses (the uniqueness tag goes in the local part).
_VERIFIED_DOMAIN = "verified.example.test"

_COUNT_TABLES = (
    "users",
    "external_identities",
    "organizations",
    "memberships",
    "api_keys",
    "audit_events",
)


def _claims(sub: str = _SUB) -> CognitoClaims:
    return CognitoClaims(
        sub=sub,
        email=None,
        username="Racer",
        client_id="race-client",
        iss="https://cognito.us-east-1.amazonaws.com/us-east-1_pool",
        exp=2000000000,
    )


def _verified_email(sub: str) -> str:
    """The user-info email belonging to ``sub``.

    Derived from the subject instead of hardcoded: one subject means one
    verified email (what a real concurrent first-login looks like). No
    assertion depends on the *value* — the service reads the batch email from
    the gated profile and converges on the identity tuple alone; the one
    email assertion below only checks membership in the offered set.
    """
    return f"{sub}@{_VERIFIED_DOMAIN}"


def _profile(sub: str = _SUB, *, email: str | None = None) -> CognitoProfile:
    """The verified user-info profile the provisioning path now requires
    (Phase 11 task 5): the batch email comes from here, not from claims."""
    return CognitoProfile(
        sub=sub,
        email=_verified_email(sub) if email is None else email,
        email_verified=True,
        display_name="Racer",
    )


def _table_counts(path: Path) -> dict[str, int]:
    conn = sqlite3.connect(path)
    try:
        return {
            table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in _COUNT_TABLES
        }
    finally:
        conn.close()


def _shared_profile(_attempt: int) -> CognitoProfile:
    """Default race fixture: one subject, so one derived verified email."""
    return _profile()


def _run_race_once(
    tmp_path: Path,
    *,
    profile_for: Callable[[int], CognitoProfile] = _shared_profile,
) -> User:
    """One 8-way first-login race on a fresh database; returns the winner.

    ``profile_for`` maps an attempt index to that attempt's verified profile;
    the default gives every attempt the same subject-derived profile (the
    realistic same-user race), while an explicit factory can vary the email
    per attempt to prove convergence never depends on it.
    """
    path = tmp_path / "race.sqlite"
    storage = open_sqlite_storage(path)
    try:
        # Main-thread warm-up: a pure read that initializes the file (schema,
        # WAL) *outside* the timed window and proves the tuple is empty.
        with pytest.raises(EntityNotFoundError):
            storage.get_user_by_external_identity(
                provider=IdentityProvider.COGNITO,
                provider_subject=_SUB,
                provider_tenant=None,
            )

        barrier = threading.Barrier(_THREADS)
        results: list[BaseException | ResolvedIdentity] = []
        results_lock = threading.Lock()

        def worker(attempt: int) -> None:
            barrier.wait()
            try:
                # No injected ids/timestamps: every attempt mints its own
                # batch, exactly like two real first-login requests. Each
                # carries its own fake profile provider (Phase 11 task 5).
                outcome: BaseException | ResolvedIdentity = resolve_or_provision(
                    storage, _claims(), profile_provider=lambda: profile_for(attempt)
                )
            except BaseException as exc:
                outcome = exc
            with results_lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker, args=(attempt,)) for attempt in range(_THREADS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == _THREADS
        resolved = [item for item in results if isinstance(item, ResolvedIdentity)]
        errors = [item for item in results if not isinstance(item, ResolvedIdentity)]
        assert not errors, f"concurrent first logins must all converge: {errors!r}"
        assert len(resolved) == _THREADS

        user_ids = {str(item.user.id) for item in resolved}
        org_ids = {str(item.context.organization_id) for item in resolved}
        assert len(user_ids) == 1, "every thread must resolve the same usr_"
        assert len(org_ids) == 1, "every thread must resolve the same org_"
    finally:
        storage.close()

    # Direct fresh reads (a new adapter instance, not the racers' views).
    assert _table_counts(path) == {
        "users": 1,
        "external_identities": 1,
        "organizations": 1,
        "memberships": 1,
        "api_keys": 0,
        "audit_events": 3,
    }
    verifier = open_sqlite_storage(path)
    try:
        winner = verifier.get_user_by_external_identity(
            provider=IdentityProvider.COGNITO,
            provider_subject=_SUB,
            provider_tenant=None,
        )
        assert str(winner.id) == next(iter(user_ids))
        conn = sqlite3.connect(path)
        try:
            actions = {row[0] for row in conn.execute("SELECT action FROM audit_events")}
        finally:
            conn.close()
        assert actions == {"user.created", "organization.created", "membership.created"}
    finally:
        verifier.close()
    return winner


@pytest.mark.parametrize("repeat", range(_REPEATS))
def test_concurrent_first_requests_provision_exactly_once(tmp_path: Path, repeat: int) -> None:
    """20 independent 8-way races; each must converge on one tenant."""
    race_dir = tmp_path / f"race-{repeat}"
    race_dir.mkdir()
    _run_race_once(race_dir)


def test_concurrent_race_converges_regardless_of_batch_email(tmp_path: Path) -> None:
    """§6 convergence is keyed on the identity tuple, never on the email.

    Every attempt offers a *different* verified email for the same ``sub``:
    the loser's batch then violates the identity-tuple UNIQUE instead of
    ``users.email``, and the service still converges on the winner through
    the identity-tuple re-read. This is what frees the race fixture from a
    shared placeholder email — the stored email is simply the winner's.
    """

    def email_for(attempt: int) -> str:
        # Plus-addressing in the *local* part: distinct per attempt, and each
        # value stays a well-formed address (User.email pins length only, not
        # format, so a malformed fixture would pass for the wrong reason).
        return f"{_SUB}+{attempt}@{_VERIFIED_DOMAIN}"

    winner = _run_race_once(
        tmp_path,
        profile_for=lambda attempt: _profile(email=email_for(attempt)),
    )
    assert winner.email in {email_for(attempt) for attempt in range(_THREADS)}


def test_distinct_subs_same_email_conflict_without_partial_rows(tmp_path: Path) -> None:
    """Not a race: a genuine email collision. First provisions, second gets
    ProvisioningConflictError (decision 7), and nothing partial is left."""
    path = tmp_path / "collision.sqlite"
    storage = open_sqlite_storage(path)
    try:
        first = resolve_or_provision(
            storage,
            _claims(sub="sub-owner"),
            profile_provider=lambda: _profile("sub-owner", email=_COLLISION_EMAIL),
        )
        with pytest.raises(ProvisioningConflictError):
            resolve_or_provision(
                storage,
                _claims(sub="sub-stranger"),
                profile_provider=lambda: _profile("sub-stranger", email=_COLLISION_EMAIL),
            )
    finally:
        storage.close()

    assert _table_counts(path) == {
        "users": 1,  # only the first user; the stranger's batch rolled back fully
        "external_identities": 1,
        "organizations": 1,
        "memberships": 1,
        "api_keys": 0,
        "audit_events": 3,
    }
    storage2 = open_sqlite_storage(path)
    try:
        stored = storage2.get_user_by_external_identity(
            provider=IdentityProvider.COGNITO,
            provider_subject="sub-owner",
            provider_tenant=None,
        )
        assert str(stored.id) == str(first.user.id)
        assert stored.email == _COLLISION_EMAIL  # the batch email is the profile's
        with pytest.raises(EntityNotFoundError):
            storage2.get_user_by_external_identity(
                provider=IdentityProvider.COGNITO,
                provider_subject="sub-stranger",
                provider_tenant=None,
            )
    finally:
        storage2.close()
