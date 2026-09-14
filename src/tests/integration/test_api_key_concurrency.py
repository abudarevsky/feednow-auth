"""Concurrency and duplicate-request acceptance proofs (Phase 05 task 7, part c).

The AGENTS.md concurrency mandate ("provisioning and credential revocation
are concurrency-sensitive: define and test atomicity and duplicate-request
behavior") at the Phase 05 HTTP seam, on the proven Phase 03/04 pattern:
``threading.Barrier`` releases (never sleeps), 20 parameterized repeats for
stability, main-thread warm-up reads, and every final count asserted through
**direct** SQLite reads on a fresh connection. Lock handling relies entirely
on the adapter's existing ``busy_timeout`` + WAL discipline — nothing is
added to production code here.

Cases (breakdown task 7(c)):

1. **8 concurrent revocations of one key** — every call is an idempotent
   success (all 204, decision 10), the stored row carries exactly **one**
   ``revoked_at`` (the CAS winner's timestamp — which is also one of the
   audited timestamps, proving the winner's own audit carried the stored
   truth), and each processed call appended its own truthful ``api_key.revoked``
   audit (8 rows; duplicate suppression would need winner-detection that
   same-clock ties defeat). A verifier thread interleaves ``verify_api_key``
   polls across the whole race: the credential authenticates before the
   barrier, the observed sequence is **monotonic** (never ``401 → 200``), and
   after the race verification fails — the contract's "immediately effective"
   proof with no cache in the service.
2. **8 concurrent creations with the same body** — creation is non-idempotent
   by design (decision 9): eight 201s, eight distinct ``key_`` identities,
   eight distinct §8 segments and secrets, eight distinct literals, eight
   ``api_key.created`` audits — no shared or reused credential material.
3. **Forced collision from the minting generator** (monkeypatched ids) — the
   UNIQUE index is the arbiter (decision 11): the POST answers 409
   ``conflict`` with the fixed retry message, the stored row count is
   unchanged, and **zero** audit rows exist (the audit append happens only
   after a successful write, so a rejected create leaves no trace). Both
   collision kinds are proven: the §8 ``key_id`` segment
   (``api_keys_key_id_unique``) and the ``key_`` record id.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from support.cognito import JwksTestServer, TestKey, generate_test_key, sign_token

from app.api.keys import build_api_keys_router
from app.auth.api_key_auth import ApiKeyAuthenticationError, verify_api_key
from app.auth.cognito import CognitoAccessTokenVerifier
from app.auth.credentials import generate_key_id, generate_secret, hash_secret, parse_literal
from app.auth.jwks import CognitoJwksSource
from app.auth.pepper import StaticPepper
from app.main import create_app
from app.models.api_key import ApiKey
from app.models.enums import (
    ApiKeyEnvironment,
    ApiKeyStatus,
    IdentityProvider,
    MembershipRole,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.errors import Error
from app.models.external_identity import ExternalIdentity
from app.models.ids import (
    ApiKeyId,
    ExternalIdentityId,
    MembershipId,
    OrganizationId,
    UserId,
)
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.user import User
from app.services import api_key_service
from app.services.api_key_service import ApiKeyCreationIds, build_key_prefix
from app.services.idgen import new_api_key_id, new_audit_event_id
from app.storage.sqlite import SQLiteStorage

_REPEATS = 20
_THREADS = 8
_T0 = datetime(2026, 9, 14, 18, 0, 0, tzinfo=UTC)
_ALLOWED_CLIENT = "key-race-client"

#: Same fixed 36-byte test pepper as the task-1..6/7 suites (never production;
#: satisfies the StaticPepper ≥32-byte enforcement, decision 3).
PEPPER = b"integration-race-pepper-0123456789ab"

RUN_SCOPE = "vispector:inspection:run"
READ_SCOPE = "vispector:inspection:read"

#: 26-char Crockford segment (underscore-free by charset, decision 2) used as
#: the pre-existing row the forced collisions race against.
SEG_COLLIDED = "01JXYZ7KA20MB63PCQ8VNDWFTG"
SEED_SECRET = "aE-W-K9J0KCdH1pnlK_BGZGEcs8xWSr3tTiSKGVPFXo"


# ---------------------------------------------------------------------------
# Seeding helpers (the Phase 04 race-test shape)
# ---------------------------------------------------------------------------


def _seed_user(storage: SQLiteStorage, user_id: str, sub: str, email: str) -> None:
    storage.create_user(
        User(
            id=UserId(user_id),
            display_name=f"race {user_id}",
            email=email,
            status=UserStatus.ACTIVE,
            created_at=_T0,
            updated_at=_T0,
        )
    )
    storage.create_external_identity(
        ExternalIdentity(
            id=ExternalIdentityId(f"extid_{user_id.removeprefix('usr_')}"),
            user_id=UserId(user_id),
            provider=IdentityProvider.COGNITO,
            provider_subject=sub,
            provider_tenant=None,
            created_at=_T0,
        )
    )


def _seed_team(storage: SQLiteStorage) -> None:
    """One owner on one active organization — the whole cast the races need."""
    _seed_user(storage, "usr_owner", "owner-sub", "owner@example.test")
    storage.create_organization(
        Organization(
            id=OrganizationId("org_team"),
            name="race org",
            slug="race-team",
            type=OrganizationType.CUSTOMER,
            status=OrganizationStatus.ACTIVE,
            created_at=_T0,
            updated_at=_T0,
        )
    )
    storage.create_membership(
        Membership(
            id=MembershipId("mem_owner"),
            organization_id=OrganizationId("org_team"),
            user_id=UserId("usr_owner"),
            role=MembershipRole.OWNER,
            status="active",
            created_at=_T0,
        )
    )


def _seed_key(storage: SQLiteStorage, *, api_key_id: str, key_id_segment: str) -> ApiKey:
    """Write one active key row directly (the forced-collision anchor)."""
    return storage.create_api_key(
        ApiKey(
            id=ApiKeyId(api_key_id),
            organization_id=OrganizationId("org_team"),
            created_by_user_id=UserId("usr_owner"),
            name=f"seeded {api_key_id}",
            key_id=key_id_segment,
            key_prefix=build_key_prefix(ApiKeyEnvironment.LIVE, key_id_segment, SEED_SECRET),
            secret_hash=hash_secret(PEPPER, SEED_SECRET),
            environment=ApiKeyEnvironment.LIVE,
            scopes=[READ_SCOPE],
            status=ApiKeyStatus.ACTIVE,
            created_at=_T0,
        )
    )


# ---------------------------------------------------------------------------
# Direct-read helpers (no audit read surface exists; counts come from SQLite)
# ---------------------------------------------------------------------------


def _rows(db_path: Path, table: str) -> list[dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table}").fetchall()]
    finally:
        conn.close()


def _key_row(db_path: Path, api_key_id: str) -> dict[str, Any]:
    found = [row for row in _rows(db_path, "api_keys") if row["id"] == api_key_id]
    assert len(found) == 1, f"expected exactly one row for {api_key_id!r}, got {len(found)}"
    return found[0]


def _action_rows(db_path: Path, action: str) -> list[dict[str, Any]]:
    return [row for row in _rows(db_path, "audit_events") if row["action"] == action]


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


class _RaceEnv:
    """Shipped keys router + real SQLite + one signed owner token per race db."""

    def __init__(self, db_path: Path, server: JwksTestServer, key: TestKey) -> None:
        self.db_path = db_path
        self.storage = SQLiteStorage(db_path)
        self.pepper = StaticPepper(PEPPER)
        issuer = server.issuer("pool-a")
        verifier = CognitoAccessTokenVerifier(
            CognitoJwksSource([issuer]),
            allowed_issuers=[issuer],
            allowed_client_ids=[_ALLOWED_CLIENT],
        )
        app = create_app(routers=[build_api_keys_router(self.storage, verifier, self.pepper)])
        self.client = TestClient(app, raise_server_exceptions=False)
        now = int(time.time())
        token = sign_token(
            {
                "sub": "owner-sub",
                "email": "owner@example.test",
                "username": "user-owner",
                "client_id": _ALLOWED_CLIENT,
                "iss": issuer,
                "token_use": "access",
                "exp": now + 3600,
                "iat": now,
            },
            kid=key.kid,
            key=key,
        )
        self.headers = {"Authorization": f"Bearer {token}"}

    def create_key(self) -> dict[str, Any]:
        """One owner create through the HTTP seam; returns the 201 body."""
        response = self.client.post(
            "/v1/organizations/org_team/api-keys",
            headers=self.headers,
            json={"name": "raced", "environment": "live", "scopes": [RUN_SCOPE, READ_SCOPE]},
        )
        assert response.status_code == 201, response.content
        return response.json()

    def close(self) -> None:
        self.storage.close()


@pytest.fixture(scope="module")
def key() -> TestKey:
    return generate_test_key("key-race-key-1")


@pytest.fixture(scope="module")
def server(key: TestKey) -> Iterator[JwksTestServer]:
    with JwksTestServer({"pool-a": [key]}) as running:
        yield running


# ---------------------------------------------------------------------------
# Case 1: 8 concurrent revokes — idempotent 204s, one stored revoked_at,
# one truthful audit each, and an interleaved verification that never flips
# back to granted.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("repeat", range(_REPEATS))
def test_concurrent_revokes_are_idempotent_and_verification_never_flips_back(
    server: JwksTestServer, key: TestKey, tmp_path: Path, repeat: int
) -> None:
    race_dir = tmp_path / f"revoke-{repeat}"
    race_dir.mkdir()
    env = _RaceEnv(race_dir / "revoke_race.sqlite", server, key)
    try:
        _seed_team(env.storage)
        created = env.create_key()
        api_key_id = str(created["id"])
        literal = str(created["key"])
        path = f"/v1/organizations/org_team/api-keys/{api_key_id}"

        # Pre-race truth (also the main-thread warm-up reads): the credential
        # authenticates and the row is active before anyone races.
        verified = verify_api_key(env.storage, env.pepper, literal)
        assert verified.api_key.id == ApiKeyId(api_key_id)
        assert verified.api_key.status is ApiKeyStatus.ACTIVE
        assert (
            env.client.get("/v1/organizations/org_team/api-keys", headers=env.headers).status_code
            == 200
        )

        barrier = threading.Barrier(_THREADS + 1)
        statuses: list[int] = []
        trace: list[bool] = []
        lock = threading.Lock()
        stop = threading.Event()

        def revoker() -> None:
            barrier.wait()
            response = env.client.delete(path, headers=env.headers)
            with lock:
                statuses.append(response.status_code)

        def watcher() -> None:
            """Poll verification continuously across the whole race window."""
            barrier.wait()
            while True:
                try:
                    verify_api_key(env.storage, env.pepper, literal)
                    granted = True
                except ApiKeyAuthenticationError:
                    granted = False
                with lock:
                    trace.append(granted)
                # Sample-then-check: the stop is set only after every revoker
                # joined, so the final sample is guaranteed to observe the
                # revoked state (deterministic, not a timing coincidence).
                if stop.is_set():
                    break

        runners = [threading.Thread(target=revoker) for _ in range(_THREADS)]
        runners.append(threading.Thread(target=watcher))
        for runner in runners:
            runner.start()
        for runner in runners[:-1]:
            runner.join()
        stop.set()
        runners[-1].join()

        # Post-race verification (still on the open adapter): the credential
        # is dead — "immediately effective" with no cache in the service.
        with pytest.raises(ApiKeyAuthenticationError):
            verify_api_key(env.storage, env.pepper, literal)
    finally:
        env.close()

    # Every duplicate/concurrent revocation is an idempotent success.
    assert statuses == [204] * _THREADS

    # One stored revoked_at: the CAS winner's timestamp, preserved for the
    # losers (their conditional UPDATE matched zero rows).
    row = _key_row(env.db_path, api_key_id)
    assert row["status"] == "revoked"
    assert row["revoked_at"] is not None

    # One truthful audit per processed call, and the stored revoked_at is one
    # of the audited timestamps — the winner's own audit carried the truth.
    revoked_audits = _action_rows(env.db_path, "api_key.revoked")
    assert len(revoked_audits) == _THREADS
    assert {audit["target_id"] for audit in revoked_audits} == {api_key_id}
    assert row["revoked_at"] in {audit["created_at"] for audit in revoked_audits}

    # The interleaved verification is monotonic: once the credential stops
    # authenticating it never authenticates again (no cache, fresh read per
    # request — "immediately effective").
    assert trace, "the watcher must have sampled across the race"
    assert False in trace, "the watcher must have observed the revoked state"
    assert True not in trace[trace.index(False) + 1 :], "verification flipped back to granted"


# ---------------------------------------------------------------------------
# Case 2: 8 concurrent creates — non-idempotent by design, eight distinct
# credentials, eight audits.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("repeat", range(_REPEATS))
def test_concurrent_creates_mint_eight_distinct_credentials(
    server: JwksTestServer, key: TestKey, tmp_path: Path, repeat: int
) -> None:
    race_dir = tmp_path / f"create-{repeat}"
    race_dir.mkdir()
    env = _RaceEnv(race_dir / "create_race.sqlite", server, key)
    try:
        _seed_team(env.storage)
        # Warm-up read initializes the file/WAL outside the timed window.
        assert (
            env.client.get("/v1/organizations/org_team/api-keys", headers=env.headers).status_code
            == 200
        )

        barrier = threading.Barrier(_THREADS)
        bodies: list[dict[str, Any]] = []
        statuses: list[int] = []
        lock = threading.Lock()

        def creator() -> None:
            barrier.wait()
            response = env.client.post(
                "/v1/organizations/org_team/api-keys",
                headers=env.headers,
                json={"name": "raced", "environment": "live", "scopes": [RUN_SCOPE]},
            )
            with lock:
                statuses.append(response.status_code)
                bodies.append(response.json())

        runners = [threading.Thread(target=creator) for _ in range(_THREADS)]
        for runner in runners:
            runner.start()
        for runner in runners:
            runner.join()

        # Every minted literal authenticates independently (still open).
        for body in bodies:
            assert verify_api_key(env.storage, env.pepper, body["key"]).api_key.id == ApiKeyId(
                body["id"]
            )
    finally:
        env.close()

    assert statuses == [201] * _THREADS
    ids = {body["id"] for body in bodies}
    literals = {body["key"] for body in bodies}
    assert len(ids) == _THREADS
    assert len(literals) == _THREADS
    segments = {parse_literal(literal).key_id for literal in literals}
    secrets = {parse_literal(literal).secret for literal in literals}
    assert len(segments) == _THREADS
    assert len(secrets) == _THREADS

    # Direct reads: eight rows, each carrying exactly its own minted segments.
    rows = _rows(env.db_path, "api_keys")
    assert len(rows) == _THREADS
    assert {row["id"] for row in rows} == ids
    assert {row["key_id"] for row in rows} == segments
    assert all(row["status"] == "active" for row in rows)

    created_audits = _action_rows(env.db_path, "api_key.created")
    assert len(created_audits) == _THREADS
    assert {audit["target_id"] for audit in created_audits} == ids


# ---------------------------------------------------------------------------
# Case 3: forced collision from the minting generator — 409, zero audit rows.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("collision_kind", ["key_id", "entity_id"])
def test_forced_credential_collision_answers_409_with_zero_audits(
    env_with_anchor: _RaceEnv, monkeypatch: pytest.MonkeyPatch, collision_kind: str
) -> None:
    env = env_with_anchor
    if collision_kind == "key_id":
        # The §8 segment repeats; the key_ record id stays fresh.
        def forced() -> ApiKeyCreationIds:
            return ApiKeyCreationIds(
                api_key_id=new_api_key_id(),
                audit_id=new_audit_event_id(),
                key_id=SEG_COLLIDED,
                secret=generate_secret(),
            )
    else:
        # The key_ record id repeats; the §8 segment stays fresh.
        def forced() -> ApiKeyCreationIds:
            return ApiKeyCreationIds(
                api_key_id=ApiKeyId("key_anchor"),
                audit_id=new_audit_event_id(),
                key_id=generate_key_id(),
                secret=generate_secret(),
            )

    monkeypatch.setattr(api_key_service, "new_api_key_creation_ids", forced)

    response = env.client.post(
        "/v1/organizations/org_team/api-keys",
        headers=env.headers,
        json={"name": "collision", "environment": "live", "scopes": [RUN_SCOPE]},
    )

    assert response.status_code == 409
    envelope = Error.model_validate(response.json())
    assert envelope.code == "conflict"
    # Fixed retry message: no caller text, no credential material echoed.
    assert "retry" in envelope.message.lower()
    assert SEG_COLLIDED not in response.text
    assert SEED_SECRET not in response.text

    # The rejected create left no trace: the anchor row is untouched and the
    # audit append never ran (it happens only after a successful write).
    assert len(_rows(env.db_path, "api_keys")) == 1
    anchor = _key_row(env.db_path, "key_anchor")
    assert anchor["status"] == "active"
    assert anchor["revoked_at"] is None
    assert _rows(env.db_path, "audit_events") == []


@pytest.fixture
def env_with_anchor(tmp_path: Path, server: JwksTestServer, key: TestKey) -> Iterator[_RaceEnv]:
    """Race environment with one pre-existing key row anchoring the collisions."""
    env = _RaceEnv(tmp_path / "collision.sqlite", server, key)
    _seed_team(env.storage)
    _seed_key(env.storage, api_key_id="key_anchor", key_id_segment=SEG_COLLIDED)
    try:
        yield env
    finally:
        env.close()
