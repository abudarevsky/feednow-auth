"""Tests for the Phase 05 task-3 API-key verification seam (:mod:`app.auth.api_key_auth`).

Covers the task-3 Verify line (breakdown decision 4/5): the fixed-order
verification pipeline, the one uniform authentication failure, and the §10
API-key context. Two storage backings are exercised —

* a recording :class:`StubKeyStorage` for the full failure **matrix** and the
  call-count proofs (no database, deterministic clock), and
* the **real Phase 02 SQLite adapter** for a round-trip of a genuinely stored
  credential (seeded directly, since no create API path exists yet — decision 12).

The acceptance-critical pins proven here:

- every failure — malformed-each-way, unknown key-id, wrong secret (1-bit
  flip), environment skew, revoked, expired, and the ``expires_at == now``
  boundary — raises the **identical** :class:`ApiKeyAuthenticationError`
  message, and no key-id/secret/pepper fragment appears in any exception,
  cause, or context (no segment oracle on the message axis);
- the unknown-key-id branch performs the **dummy constant-time comparison**
  exactly once and never the real one, while every found-key branch performs
  the real comparison exactly once and never the dummy (timing-axis
  equalization, decision 4);
- a malformed literal is rejected **before** the pepper source or storage is
  touched, and a non-``EntityNotFoundError`` ``StorageError`` propagates
  untranslated (decision 11 → 500, never a misleading 401);
- the success context is ``actor_type="api_key"``, ``actor_id=`` the ``key_``
  application identity, ``roles == []`` (no human escalation), and the stored
  scopes; ``key_has_scope`` is exact-match only (no wildcards/hierarchy).
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.auth import api_key_auth
from app.auth.api_key_auth import (
    API_KEY_AUTHENTICATION_MESSAGE,
    ApiKeyAuthenticationError,
    VerifiedApiKey,
    build_api_key_context,
    key_has_scope,
    verify_api_key,
)
from app.auth.credentials import build_literal, hash_secret
from app.auth.pepper import StaticPepper
from app.models.api_key import ApiKey
from app.models.enums import (
    ApiKeyEnvironment,
    ApiKeyStatus,
    OrganizationStatus,
    OrganizationType,
    UserStatus,
)
from app.models.ids import ApiKeyId, OrganizationId, UserId
from app.models.organization import Organization
from app.models.user import User
from app.storage.contract import EntityNotFoundError, StorageError
from app.storage.sqlite import open_sqlite_storage

# Same fixed 32-byte test pepper as the task-1/2 suites (≥32 bytes, never
# production material).
PEPPER = b"unit-test-pepper-32-bytes-fixed!"

# 26 chars, Crockford base32 only, underscore-free by charset (decision 2).
KEY_ID = "01JXYZ7KA20MB63PCQ8VNDWFTG"
# A second valid segment for the unknown-key-id case (first char '7' is inside
# the ``0-7`` timestamp range; all chars are legal Crockford).
UNKNOWN_KEY_ID = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
# 43 base64url chars decoding to 256 bits, deliberately containing ``_``/``-``.
SECRET = "aE-W-K9J0KCdH1pnlK_BGZGEcs8xWSr3tTiSKGVPFXo"
# A single-character flip of the secret: a valid, non-empty secret whose
# peppered HMAC differs from the stored digest (the "wrong secret" branch).
WRONG_SECRET = SECRET[:-1] + ("A" if SECRET[-1] != "A" else "B")

ORG = OrganizationId("org_" + "b" * 32)
ACTOR = UserId("usr_" + "d" * 32)
KEY_IDENTITY = ApiKeyId("key_" + "a" * 32)

NOW = datetime(2026, 9, 13, 8, 30, 0, tzinfo=UTC)
_SCOPES = ["vispector:inspection:run", "vispector:inspection:write"]


def _stored_key(
    *,
    environment: ApiKeyEnvironment = ApiKeyEnvironment.LIVE,
    status: ApiKeyStatus = ApiKeyStatus.ACTIVE,
    scopes: Sequence[str] = _SCOPES,
    expires_at: datetime | None = None,
    secret: str = SECRET,
    key_id: str = KEY_ID,
    api_key_id: ApiKeyId = KEY_IDENTITY,
    organization_id: OrganizationId = ORG,
) -> ApiKey:
    """Build a complete ``ApiKey`` row with the peppered HMAC of ``secret``."""
    return ApiKey(
        id=api_key_id,
        organization_id=organization_id,
        created_by_user_id=ACTOR,
        name="CI runner",
        key_id=key_id,
        key_prefix=f"fn_{environment.value}_{key_id}",
        secret_hash=hash_secret(PEPPER, secret),
        environment=environment,
        scopes=list(scopes),
        status=status,
        created_at=NOW,
        expires_at=expires_at,
    )


class StubKeyStorage:
    """Minimal recording ``Storage`` stub exposing only the §8 point lookup.

    Records every ``get_api_key_by_key_id`` call so tests can prove malformed
    literals never reach storage and that the unknown-key branch runs the
    dummy comparison instead of a real one.
    """

    def __init__(self) -> None:
        self.by_segment: dict[str, ApiKey] = {}
        self.calls: list[str] = []
        self.get_error: StorageError | None = None

    def get_api_key_by_key_id(self, key_id: str) -> ApiKey:
        self.calls.append("get_api_key_by_key_id")
        if self.get_error is not None:
            raise self.get_error
        api_key = self.by_segment.get(key_id)
        if api_key is None:
            raise EntityNotFoundError("no api key carries that credential segment")
        return api_key

    def seed(self, api_key: ApiKey) -> ApiKey:
        self.by_segment[api_key.key_id] = api_key
        return api_key


class CountingPepper:
    """A :class:`PepperSource` that counts ``current()`` calls."""

    def __init__(self, pepper: bytes = PEPPER) -> None:
        self._pepper = pepper
        self.calls = 0

    def current(self) -> bytes:
        self.calls += 1
        return self._pepper


def _assert_uniform_failure(exc: BaseException) -> None:
    """Every authentication failure is the identical fixed message."""
    assert isinstance(exc, ApiKeyAuthenticationError)
    assert str(exc) == API_KEY_AUTHENTICATION_MESSAGE


def _chain_text(exc: BaseException) -> str:
    """Collect every string across the exception's cause/context chain."""
    seen: list[str] = []
    pending: list[BaseException] = [exc]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in visited:  # pragma: no cover - guards cycles
            continue
        visited.add(id(current))
        seen.append(str(current))
        seen.append(repr(current))
        seen.extend(repr(arg) for arg in current.args)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return "\n".join(seen)


@pytest.fixture
def compare_counts(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Wrap the real/dummy comparisons with call counters (behavior unchanged)."""
    real = api_key_auth.secret_matches
    dummy = api_key_auth.dummy_secret_matches
    counts = {"real": 0, "dummy": 0}

    def counting_real(*args: object, **kwargs: object) -> bool:
        counts["real"] += 1
        return real(*args, **kwargs)  # type: ignore[arg-type]

    def counting_dummy(*args: object, **kwargs: object) -> bool:
        counts["dummy"] += 1
        return dummy(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(api_key_auth, "secret_matches", counting_real)
    monkeypatch.setattr(api_key_auth, "dummy_secret_matches", counting_dummy)
    return counts


# ---------------------------------------------------------------------------
# Success path (stub)
# ---------------------------------------------------------------------------


def test_verify_success_returns_key_and_decision_5_context() -> None:
    storage = StubKeyStorage()
    seeded = storage.seed(_stored_key())
    literal = build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET)

    result = verify_api_key(storage, StaticPepper(PEPPER), literal, now=NOW)

    assert isinstance(result, VerifiedApiKey)
    assert result.api_key == seeded
    context = result.context
    assert context.actor_type == "api_key"
    assert context.actor_id == KEY_IDENTITY
    assert isinstance(context.actor_id, ApiKeyId)
    assert context.organization_id == ORG
    assert context.roles == []
    assert context.scopes == _SCOPES


def test_verify_success_without_expiry_ignores_clock() -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key(expires_at=None))

    # No expiry: verification succeeds with no ``now`` supplied at all.
    result = verify_api_key(
        storage, StaticPepper(PEPPER), build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET)
    )
    assert result.context.actor_id == KEY_IDENTITY


def test_verify_success_when_expiry_is_in_the_future() -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key(expires_at=NOW + timedelta(microseconds=1)))

    result = verify_api_key(
        storage,
        StaticPepper(PEPPER),
        build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET),
        now=NOW,
    )
    assert result.api_key.status is ApiKeyStatus.ACTIVE


# ---------------------------------------------------------------------------
# Failure matrix: identical message, no segment oracle
# ---------------------------------------------------------------------------

# Each entry: (label, seed-key-builder-or-None, literal). ``None`` seed means
# nothing is stored (unknown key-id). Malformed literals never reach storage.
_MALFORMED_LITERALS = [
    ("no-prefix", "not_a_credential_at_all"),
    ("wrong-env-token", f"fn_prod_{KEY_ID}_{SECRET}"),
    ("missing-secret-separator", f"fn_live_{KEY_ID}"),
    ("empty-secret", f"fn_live_{KEY_ID}_"),
    ("bad-key-id-char", f"fn_live_{'I' * 26}_{SECRET}"),
    ("short-key-id", f"fn_live_SHORT_{SECRET}"),
    ("oversized", f"fn_live_{KEY_ID}_{'a' * 600}"),
    ("empty", ""),
]


@pytest.mark.parametrize(("label", "literal"), _MALFORMED_LITERALS)
def test_malformed_literal_fails_uniformly_without_touching_storage(
    label: str, literal: str
) -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key())

    with pytest.raises(ApiKeyAuthenticationError) as excinfo:
        verify_api_key(storage, StaticPepper(PEPPER), literal, now=NOW)

    _assert_uniform_failure(excinfo.value)
    # Format failure precedes any storage read (decision 4 step (a)).
    assert storage.calls == []
    # No credential fragment leaks into the exception chain.
    for fragment in (KEY_ID, SECRET, PEPPER.decode(), literal):
        if fragment:
            assert fragment not in _chain_text(excinfo.value)


def test_unknown_key_id_fails_uniformly() -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key())  # a different, unrelated key is present
    literal = build_literal(ApiKeyEnvironment.LIVE, UNKNOWN_KEY_ID, SECRET)

    with pytest.raises(ApiKeyAuthenticationError) as excinfo:
        verify_api_key(
            storage,
            StaticPepper(PEPPER),
            literal,
            now=NOW,
        )

    _assert_uniform_failure(excinfo.value)
    assert storage.calls == ["get_api_key_by_key_id"]
    # The miss is surfaced as the uniform failure with the storage error's
    # context deliberately suppressed (``raise ... from None``): no cause is
    # attached and the traceback context is hidden. (``__context__`` is still
    # the ``EntityNotFoundError`` Python attaches automatically, but its fixed
    # message carries no credential bytes — proven by the sweep below.)
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__ is True
    # No segment oracle even through the suppressed context chain.
    chain = _chain_text(excinfo.value)
    for fragment in (UNKNOWN_KEY_ID, SECRET, PEPPER.decode(), literal):
        assert fragment not in chain


def test_wrong_secret_one_bit_flip_fails_uniformly() -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key())

    with pytest.raises(ApiKeyAuthenticationError) as excinfo:
        verify_api_key(
            storage,
            StaticPepper(PEPPER),
            build_literal(ApiKeyEnvironment.LIVE, KEY_ID, WRONG_SECRET),
            now=NOW,
        )

    _assert_uniform_failure(excinfo.value)
    assert WRONG_SECRET not in _chain_text(excinfo.value)


def test_environment_prefix_store_mismatch_fails_uniformly() -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key(environment=ApiKeyEnvironment.LIVE))

    # Correct key-id + secret, but a ``fn_test_`` prefix against a ``live`` row.
    with pytest.raises(ApiKeyAuthenticationError) as excinfo:
        verify_api_key(
            storage,
            StaticPepper(PEPPER),
            build_literal(ApiKeyEnvironment.TEST, KEY_ID, SECRET),
            now=NOW,
        )

    _assert_uniform_failure(excinfo.value)


def test_revoked_key_fails_uniformly() -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key(status=ApiKeyStatus.REVOKED))

    with pytest.raises(ApiKeyAuthenticationError) as excinfo:
        verify_api_key(
            storage,
            StaticPepper(PEPPER),
            build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET),
            now=NOW,
        )

    _assert_uniform_failure(excinfo.value)


def test_expired_key_fails_uniformly() -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key(expires_at=NOW - timedelta(seconds=1)))

    with pytest.raises(ApiKeyAuthenticationError) as excinfo:
        verify_api_key(
            storage,
            StaticPepper(PEPPER),
            build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET),
            now=NOW,
        )

    _assert_uniform_failure(excinfo.value)


def test_expiry_boundary_equal_now_is_expired() -> None:
    """The ``<`` vs ``<=`` pin: ``expires_at == now`` is treated as expired."""
    storage = StubKeyStorage()
    storage.seed(_stored_key(expires_at=NOW))

    with pytest.raises(ApiKeyAuthenticationError) as excinfo:
        verify_api_key(
            storage,
            StaticPepper(PEPPER),
            build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET),
            now=NOW,
        )

    _assert_uniform_failure(excinfo.value)


def test_every_failure_message_is_byte_identical() -> None:
    """One fixed message across the whole matrix — no failure oracle."""
    storage = StubKeyStorage()
    storage.seed(_stored_key())
    revoked = StubKeyStorage()
    revoked.seed(_stored_key(status=ApiKeyStatus.REVOKED))
    expired = StubKeyStorage()
    expired.seed(_stored_key(expires_at=NOW - timedelta(seconds=1)))

    cases: list[tuple[StubKeyStorage, str]] = [
        (storage, "totally-malformed"),
        (storage, build_literal(ApiKeyEnvironment.LIVE, UNKNOWN_KEY_ID, SECRET)),
        (storage, build_literal(ApiKeyEnvironment.LIVE, KEY_ID, WRONG_SECRET)),
        (storage, build_literal(ApiKeyEnvironment.TEST, KEY_ID, SECRET)),
        (revoked, build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET)),
        (expired, build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET)),
    ]
    messages: set[str] = set()
    for stub, literal in cases:
        with pytest.raises(ApiKeyAuthenticationError) as excinfo:
            verify_api_key(stub, StaticPepper(PEPPER), literal, now=NOW)
        messages.add(str(excinfo.value))

    assert messages == {API_KEY_AUTHENTICATION_MESSAGE}
    assert API_KEY_AUTHENTICATION_MESSAGE == "invalid API key credentials"


# ---------------------------------------------------------------------------
# Timing-equalization: dummy-compare call-count proof
# ---------------------------------------------------------------------------


def test_unknown_key_id_runs_dummy_compare_not_real(compare_counts: dict[str, int]) -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key())

    with pytest.raises(ApiKeyAuthenticationError):
        verify_api_key(
            storage,
            StaticPepper(PEPPER),
            build_literal(ApiKeyEnvironment.LIVE, UNKNOWN_KEY_ID, SECRET),
            now=NOW,
        )

    assert compare_counts == {"real": 0, "dummy": 1}


def test_found_key_runs_real_compare_not_dummy(compare_counts: dict[str, int]) -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key())

    verify_api_key(
        storage,
        StaticPepper(PEPPER),
        build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET),
        now=NOW,
    )

    assert compare_counts == {"real": 1, "dummy": 0}


def test_wrong_secret_found_key_runs_real_compare_only(compare_counts: dict[str, int]) -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key())

    with pytest.raises(ApiKeyAuthenticationError):
        verify_api_key(
            storage,
            StaticPepper(PEPPER),
            build_literal(ApiKeyEnvironment.LIVE, KEY_ID, WRONG_SECRET),
            now=NOW,
        )

    assert compare_counts == {"real": 1, "dummy": 0}


def test_revoked_key_still_runs_real_compare_before_status_gate(
    compare_counts: dict[str, int],
) -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key(status=ApiKeyStatus.REVOKED))

    with pytest.raises(ApiKeyAuthenticationError):
        verify_api_key(
            storage,
            StaticPepper(PEPPER),
            build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET),
            now=NOW,
        )

    # The secret is checked before the status gate, so the timing profile of a
    # revoked-key rejection matches a wrong-secret rejection.
    assert compare_counts == {"real": 1, "dummy": 0}


# ---------------------------------------------------------------------------
# Ordering and propagation guarantees
# ---------------------------------------------------------------------------


def test_pepper_resolved_once_per_verification() -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key())
    pepper = CountingPepper()

    verify_api_key(storage, pepper, build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET), now=NOW)

    assert pepper.calls == 1


def test_malformed_literal_never_resolves_pepper() -> None:
    storage = StubKeyStorage()
    storage.seed(_stored_key())
    pepper = CountingPepper()

    with pytest.raises(ApiKeyAuthenticationError):
        verify_api_key(storage, pepper, "no-prefix-here", now=NOW)

    assert pepper.calls == 0


def test_non_notfound_storage_error_propagates_untranslated() -> None:
    """Decision 11: a backend outage is not a bad credential → never a 401."""
    storage = StubKeyStorage()
    storage.get_error = StorageError("backend down")

    with pytest.raises(StorageError) as excinfo:
        verify_api_key(
            storage,
            StaticPepper(PEPPER),
            build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET),
            now=NOW,
        )

    assert type(excinfo.value) is StorageError
    assert not isinstance(excinfo.value, ApiKeyAuthenticationError)


# ---------------------------------------------------------------------------
# build_api_key_context (decision 5)
# ---------------------------------------------------------------------------


def test_build_api_key_context_shape() -> None:
    api_key = _stored_key()

    context = build_api_key_context(api_key)

    assert context.actor_type == "api_key"
    assert context.actor_id == api_key.id
    assert isinstance(context.actor_id, ApiKeyId)
    assert context.organization_id == api_key.organization_id
    assert context.roles == []
    assert context.scopes == list(api_key.scopes)


def test_build_api_key_context_never_leaks_creator_or_segment() -> None:
    api_key = _stored_key()

    context = build_api_key_context(api_key)

    # The actor is the ``key_`` application identity, never the creator ``usr_``
    # nor the non-secret credential segment.
    assert context.actor_id != api_key.created_by_user_id
    assert str(context.actor_id) == str(api_key.id)
    assert str(context.actor_id) != api_key.key_id


def test_build_api_key_context_empty_scopes_round_trip() -> None:
    context = build_api_key_context(_stored_key(scopes=[]))
    assert context.scopes == []
    assert context.roles == []


# ---------------------------------------------------------------------------
# key_has_scope (decision 7: exact match only)
# ---------------------------------------------------------------------------


def test_key_has_scope_exact_match() -> None:
    context = build_api_key_context(_stored_key())

    assert key_has_scope(context, "vispector:inspection:run") is True
    assert key_has_scope(context, "vispector:inspection:write") is True


def test_key_has_scope_rejects_absent_and_wildcards() -> None:
    context = build_api_key_context(_stored_key())

    assert key_has_scope(context, "vispector:inspection:delete") is False
    # No wildcard/hierarchy is invented (decision 7).
    assert key_has_scope(context, "vispector:inspection:*") is False
    assert key_has_scope(context, "vispector:*") is False


# ---------------------------------------------------------------------------
# SQLite-backed round trip (real Phase 02 adapter)
# ---------------------------------------------------------------------------


@pytest.fixture
def sqlite_storage(tmp_path: Path) -> Iterator[object]:
    adapter = open_sqlite_storage(tmp_path / "api-key-auth.sqlite")
    adapter.create_user(
        User(
            id=ACTOR,
            display_name="CI",
            email="ci@example.test",
            status=UserStatus.ACTIVE,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    adapter.create_organization(
        Organization(
            id=ORG,
            name="CI Org",
            slug="ci-org",
            type=OrganizationType.PERSONAL,
            status=OrganizationStatus.ACTIVE,
            created_at=NOW,
            updated_at=NOW,
        )
    )
    try:
        yield adapter
    finally:
        adapter.close()


def _seed_sqlite(adapter: object, api_key: ApiKey) -> ApiKey:
    return adapter.create_api_key(api_key)  # type: ignore[attr-defined]


def test_sqlite_verify_valid_literal(sqlite_storage: object) -> None:
    _seed_sqlite(sqlite_storage, _stored_key())

    result = verify_api_key(
        sqlite_storage,  # type: ignore[arg-type]
        StaticPepper(PEPPER),
        build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET),
        now=NOW,
    )

    assert result.context.actor_type == "api_key"
    assert result.context.actor_id == KEY_IDENTITY
    assert result.context.scopes == _SCOPES


def test_sqlite_verify_unknown_segment_fails_uniformly(sqlite_storage: object) -> None:
    _seed_sqlite(sqlite_storage, _stored_key())

    with pytest.raises(ApiKeyAuthenticationError) as excinfo:
        verify_api_key(
            sqlite_storage,  # type: ignore[arg-type]
            StaticPepper(PEPPER),
            build_literal(ApiKeyEnvironment.LIVE, UNKNOWN_KEY_ID, SECRET),
            now=NOW,
        )

    _assert_uniform_failure(excinfo.value)


def test_sqlite_verify_revoked_key_fails_uniformly(sqlite_storage: object) -> None:
    api_key = _seed_sqlite(sqlite_storage, _stored_key())
    # Real CAS revocation transitions the stored row to ``revoked``.
    sqlite_storage.revoke_api_key(api_key.id, revoked_at=NOW)  # type: ignore[attr-defined]

    with pytest.raises(ApiKeyAuthenticationError) as excinfo:
        verify_api_key(
            sqlite_storage,  # type: ignore[arg-type]
            StaticPepper(PEPPER),
            build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET),
            now=NOW,
        )

    _assert_uniform_failure(excinfo.value)


def test_sqlite_verify_expired_key_fails_uniformly(sqlite_storage: object) -> None:
    _seed_sqlite(sqlite_storage, _stored_key(expires_at=NOW - timedelta(seconds=1)))

    with pytest.raises(ApiKeyAuthenticationError) as excinfo:
        verify_api_key(
            sqlite_storage,  # type: ignore[arg-type]
            StaticPepper(PEPPER),
            build_literal(ApiKeyEnvironment.LIVE, KEY_ID, SECRET),
            now=NOW,
        )

    _assert_uniform_failure(excinfo.value)
