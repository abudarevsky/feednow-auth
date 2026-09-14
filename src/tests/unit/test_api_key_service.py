"""Unit tests for the Phase 05 task-2 API-key service against stub storage.

These tests prove the *decision rules* of ``app.services.api_key_service``
without a database, using a recording :class:`~app.storage.contract.Storage`
stub (breakdown decision 12: zero-write proofs, exact audit shapes, injected
clock/ids). The acceptance-critical pins from decisions 9/10 exercised here:

- **create persists before it audits** — a storage failure means zero audit
  rows (both kinds of :class:`DuplicateEntityError` map to
  :class:`ApiKeyConflictError`; any other error propagates untranslated per
  decision 11), and an audit-append failure propagates uncaught with the row
  already persisted (the documented decision-1 post-commit window);
- **the plaintext never lands in storage** — the persisted row's
  ``model_dump()`` carries no secret, no literal, and no secret tail beyond
  the 6-char display head, while ``secret_hash`` equals
  ``hash_secret(pepper, secret)`` exactly;
- **foreign-org revoke raises before the CAS** — the recording stub proves
  ``revoke_api_key`` is never called, so the path is not an existence oracle,
  and the message is byte-identical to the absent-key 404;
- **duplicate revocations each append exactly one truthful audit** while the
  contract's CAS semantics (original ``revoked_at`` preserved) are honored by
  the stub, mirroring the adapter behavior tested in Phase 02.

Everything runs under injected ``now``/``ids`` so the row, the literal, and
both audit shapes are fully deterministic; real-SQLite behavior is owned by
later integration tasks.
"""

from __future__ import annotations

import json
from base64 import urlsafe_b64decode
from collections.abc import Sequence
from datetime import UTC, datetime

import pytest

from app.auth.credentials import (
    CROCKFORD_ALPHABET,
    KEY_ID_LENGTH,
    SECRET_ENTROPY_BYTES,
    ApiKeyCredentialFormatError,
    hash_secret,
    parse_literal,
)
from app.models.api_key import ApiKey
from app.models.audit_event import AuditEvent
from app.models.enums import ApiKeyEnvironment, ApiKeyStatus
from app.models.ids import ApiKeyId, AuditEventId, OrganizationId, UserId
from app.models.pagination import Page, PageParams
from app.services.api_key_service import (
    KEY_PREFIX_ELLIPSIS,
    KEY_PREFIX_SECRET_CHARS,
    ApiKeyConflictError,
    ApiKeyCreationIds,
    ApiKeyNotFoundError,
    build_api_key_created_audit,
    build_api_key_revoked_audit,
    build_key_prefix,
    create_api_key,
    list_api_keys,
    new_api_key_creation_ids,
    normalize_scopes,
    revoke_api_key,
)
from app.storage.contract import (
    DuplicateEntityError,
    DuplicateEntityKind,
    EntityNotFoundError,
    InvalidCursorError,
    ReferenceNotFoundError,
    StorageError,
)

# Same fixed 32-byte test pepper as the task-1 credential tests (≥32 bytes,
# never production material).
PEPPER = b"unit-test-pepper-32-bytes-fixed!"

_NOW = datetime(2026, 9, 13, 8, 30, 0, tzinfo=UTC)
_LATER = datetime(2026, 9, 13, 9, 45, 0, tzinfo=UTC)

_ORG = OrganizationId("org_" + "b" * 32)
_OTHER_ORG = OrganizationId("org_" + "c" * 32)
_ACTOR = UserId("usr_" + "d" * 32)

# 26 chars, Crockford base32 only (no I/L/O/U), underscore-free by charset.
_KEY_ID = "01JXYZ7KA20MB63PCQ8VNDWFTG"
# Exactly 43 base64url chars, decoding to 32 bytes (the real shape of
# ``secrets.token_urlsafe(32)``), and deliberately containing "_" and "-" so
# any parse/prefix logic is proven against the awkward alphabet. The "_" sits
# past the display head, so the first "_" after the environment prefix stays
# the key-id/secret separator (decision 2's parse rule).
_SECRET = "aE-W-K9J0KCdH1pnlK_BGZGEcs8xWSr3tTiSKGVPFXo"

_IDS = ApiKeyCreationIds(
    api_key_id=ApiKeyId("key_" + "a" * 32),
    audit_id=AuditEventId("aud_" + "e" * 32),
    key_id=_KEY_ID,
    secret=_SECRET,
)

_RAW_SCOPES = ["vispector:inspection:write", "vispector:inspection:run", "vispector:inspection:run"]
_SORTED_SCOPES = ["vispector:inspection:run", "vispector:inspection:write"]


class StubStorage:
    """Recording ``Storage`` stub implementing only the methods task 2 touches.

    ``calls`` is a single append-only order log so tests can assert not just
    counts but *sequencing* (audit strictly after the successful write, no CAS
    before the tenancy refusal). Scripted error attributes inject failures on
    each surface; ``revoke_api_key`` reproduces the contract's first-write-wins
    CAS (already-revoked → idempotent success preserving the original
    ``revoked_at``).
    """

    def __init__(self) -> None:
        self.keys: dict[str, ApiKey] = {}
        self.calls: list[str] = []
        self.audits: list[AuditEvent] = []
        # Scripted failures (raised instead of the normal behavior).
        self.create_error: StorageError | None = None
        self.get_error: StorageError | None = None
        self.revoke_error: StorageError | None = None
        self.list_error: StorageError | None = None
        self.audit_error: StorageError | None = None

    # -- API keys ------------------------------------------------------------

    def create_api_key(self, api_key: ApiKey) -> ApiKey:
        self.calls.append("create_api_key")
        if self.create_error is not None:
            raise self.create_error
        self.keys[str(api_key.id)] = api_key
        return api_key

    def get_api_key(self, api_key_id: ApiKeyId) -> ApiKey:
        self.calls.append("get_api_key")
        if self.get_error is not None:
            raise self.get_error
        api_key = self.keys.get(str(api_key_id))
        if api_key is None:
            raise EntityNotFoundError("no such api key")
        return api_key

    def revoke_api_key(self, api_key_id: ApiKeyId, *, revoked_at: datetime) -> ApiKey:
        self.calls.append("revoke_api_key")
        if self.revoke_error is not None:
            raise self.revoke_error
        api_key = self.keys.get(str(api_key_id))
        if api_key is None:
            raise EntityNotFoundError("no such api key")
        if api_key.status is ApiKeyStatus.REVOKED:
            # CAS idempotent success: original revoked_at preserved.
            return api_key
        revoked = api_key.model_copy(
            update={"status": ApiKeyStatus.REVOKED, "revoked_at": revoked_at}
        )
        self.keys[str(api_key_id)] = revoked
        return revoked

    def list_api_keys(self, organization_id: OrganizationId, page: PageParams) -> Page[ApiKey]:
        self.calls.append("list_api_keys")
        if self.list_error is not None:
            raise self.list_error
        items = sorted(
            (key for key in self.keys.values() if key.organization_id == organization_id),
            key=lambda key: (key.created_at, str(key.id)),
        )
        return Page(items=items[: page.limit], limit=page.limit, next_cursor="opaque-cursor")

    # -- audit ---------------------------------------------------------------

    def append_audit_event(self, audit_event: AuditEvent) -> None:
        self.calls.append("append_audit_event")
        if self.audit_error is not None:
            raise self.audit_error
        self.audits.append(audit_event)

    # -- helpers ---------------------------------------------------------------

    def seed(self, api_key: ApiKey) -> None:
        """Place a key row without routing through the create flow."""
        self.keys[str(api_key.id)] = api_key

    @property
    def write_calls(self) -> int:
        """Every mutation surface the service can reach."""
        return (
            self.calls.count("create_api_key")
            + self.calls.count("revoke_api_key")
            + self.calls.count("append_audit_event")
        )


def _seed_key(
    storage: StubStorage,
    *,
    api_key_id: str = "key_" + "a" * 32,
    organization_id: OrganizationId = _ORG,
    status: ApiKeyStatus = ApiKeyStatus.ACTIVE,
    revoked_at: datetime | None = None,
) -> ApiKey:
    api_key = ApiKey(
        id=ApiKeyId(api_key_id),
        organization_id=organization_id,
        created_by_user_id=_ACTOR,
        name="CI runner",
        key_id=_KEY_ID,
        key_prefix=build_key_prefix(ApiKeyEnvironment.LIVE, _KEY_ID, _SECRET),
        secret_hash=hash_secret(PEPPER, _SECRET),
        environment=ApiKeyEnvironment.LIVE,
        scopes=list(_SORTED_SCOPES),
        status=status,
        created_at=_NOW,
        revoked_at=revoked_at,
    )
    storage.seed(api_key)
    return api_key


def _create(
    storage: StubStorage,
    *,
    organization_id: OrganizationId = _ORG,
    environment: ApiKeyEnvironment = ApiKeyEnvironment.LIVE,
    scopes: Sequence[str] = _RAW_SCOPES,
    now: datetime | None = _NOW,
    ids: ApiKeyCreationIds | None = _IDS,
) -> tuple[ApiKey, str]:
    return create_api_key(
        storage,
        _ACTOR,
        organization_id,
        "CI runner",
        environment,
        scopes,
        pepper=PEPPER,
        now=now,
        ids=ids,
    )


# ---------------------------------------------------------------------------
# Pure rules: normalize_scopes / build_key_prefix
# ---------------------------------------------------------------------------


def test_normalize_scopes_sorts_and_deduplicates() -> None:
    assert normalize_scopes(_RAW_SCOPES) == _SORTED_SCOPES
    assert normalize_scopes([]) == []
    # Idempotent on already-normalized input.
    assert normalize_scopes(_SORTED_SCOPES) == _SORTED_SCOPES


def test_secret_fixture_has_the_pinned_credential_shape() -> None:
    """Pins the fixture against decision 2's real secret shape (43 base64url
    chars decoding to exactly 256 bits) so the adversarial ``_``/``-`` alphabet
    cannot silently drift into a shape no generator produces."""
    assert len(_SECRET) == 43
    assert len(urlsafe_b64decode(_SECRET + "=")) == SECRET_ENTROPY_BYTES
    assert {"_", "-"} <= set(_SECRET)


def test_build_key_prefix_matches_decision_2_shape() -> None:
    prefix = build_key_prefix(ApiKeyEnvironment.LIVE, _KEY_ID, _SECRET)
    assert prefix == f"fn_live_{_KEY_ID}_{_SECRET[:KEY_PREFIX_SECRET_CHARS]}{KEY_PREFIX_ELLIPSIS}"
    assert len(prefix) == 8 + KEY_ID_LENGTH + 1 + KEY_PREFIX_SECRET_CHARS + 3
    assert _SECRET[KEY_PREFIX_SECRET_CHARS:] not in prefix


@pytest.mark.parametrize(
    ("environment", "expected_prefix"),
    [
        (ApiKeyEnvironment.LIVE, "fn_live_"),
        (ApiKeyEnvironment.TEST, "fn_test_"),
    ],
)
def test_build_key_prefix_carries_environment_token(
    environment: ApiKeyEnvironment, expected_prefix: str
) -> None:
    assert build_key_prefix(environment, _KEY_ID, _SECRET).startswith(expected_prefix)


# ---------------------------------------------------------------------------
# Creation: persisted row, hash, literal, and secrecy sweep
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("environment", list(ApiKeyEnvironment))
def test_create_persists_complete_row_and_returns_literal_once(
    environment: ApiKeyEnvironment,
) -> None:
    storage = StubStorage()

    api_key, literal = _create(storage, environment=environment)

    stored = storage.keys[str(_IDS.api_key_id)]
    assert stored == api_key
    assert stored.id == _IDS.api_key_id
    assert stored.organization_id == _ORG
    assert stored.created_by_user_id == _ACTOR
    assert stored.name == "CI runner"
    assert stored.key_id == _KEY_ID
    assert stored.environment is environment
    assert stored.status is ApiKeyStatus.ACTIVE
    assert stored.created_at == _NOW
    # Frozen §15 request schema has no expiry field: nothing is invented (decision 9).
    assert stored.expires_at is None
    assert stored.revoked_at is None
    assert stored.last_used_at is None
    # Scopes are sorted-unique in the row (the Phase 02 round-trip contract).
    assert stored.scopes == _SORTED_SCOPES
    assert stored.key_prefix == build_key_prefix(environment, _KEY_ID, _SECRET)
    assert stored.secret_hash == hash_secret(PEPPER, _SECRET)

    # The returned literal round-trips through the task-1 parser to the exact
    # minted segments — the plaintext exists only here, returned once.
    parsed = parse_literal(literal)
    assert parsed.environment is environment
    assert parsed.key_id == _KEY_ID
    assert parsed.secret == _SECRET


def test_persisted_row_and_audit_carry_no_plaintext_material() -> None:
    storage = StubStorage()

    _, literal = _create(storage)

    # Sweep the JSON round-trip of the persisted row and the appended audit:
    # no full secret, no literal, and nothing of the secret beyond the
    # 6-char display head (the head inside key_prefix is masked
    # identification per decision 2, not a disclosure).
    blob = json.dumps(storage.keys[str(_IDS.api_key_id)].model_dump(mode="json"))
    audits_blob = json.dumps([event.model_dump(mode="json") for event in storage.audits])
    for haystack in (blob, audits_blob):
        assert _SECRET not in haystack
        assert literal not in haystack
        assert _SECRET[KEY_PREFIX_SECRET_CHARS:] not in haystack
    # The only secret-derived value stored is the peppered HMAC digest.
    assert storage.keys[str(_IDS.api_key_id)].secret_hash == hash_secret(PEPPER, _SECRET)


def test_created_audit_has_exact_decision_9_shape() -> None:
    storage = StubStorage()

    _create(storage)

    (event,) = storage.audits
    assert event.id == _IDS.audit_id
    assert event.organization_id == _ORG
    assert event.actor_type == "user"
    assert event.actor_id == _ACTOR
    assert event.action == "api_key.created"
    assert event.target_type == "api_key"
    assert event.target_id == str(_IDS.api_key_id)
    # Metadata is exactly {"environment", "scopes"} — non-secret, sorted-unique.
    assert event.metadata == {"environment": "live", "scopes": _SORTED_SCOPES}
    assert event.created_at == _NOW


# ---------------------------------------------------------------------------
# Creation: failure paths are zero-write
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", [DuplicateEntityKind.API_KEY_ID, DuplicateEntityKind.ENTITY_ID])
def test_create_duplicate_maps_to_conflict_with_zero_writes(kind: DuplicateEntityKind) -> None:
    storage = StubStorage()
    storage.create_error = DuplicateEntityError(kind, "collision")

    with pytest.raises(ApiKeyConflictError) as excinfo:
        _create(storage)

    assert isinstance(excinfo.value.__cause__, DuplicateEntityError)
    # Fixed message, no input echo; nothing persisted, nothing audited.
    assert str(excinfo.value) == "API key id collision; retry the request"
    assert storage.keys == {}
    assert storage.audits == []
    assert storage.calls == ["create_api_key"]


def test_create_reference_error_propagates_untranslated_with_zero_audits() -> None:
    """Decision 11: ``ReferenceNotFoundError`` is structurally unreachable; if
    it ever fires it is a bug and must surface untranslated (never 4xx, never
    audited)."""
    storage = StubStorage()
    storage.create_error = ReferenceNotFoundError("unknown organization")

    with pytest.raises(ReferenceNotFoundError):
        _create(storage)

    assert storage.audits == []
    assert storage.calls == ["create_api_key"]


def test_create_generic_storage_error_propagates_untranslated() -> None:
    storage = StubStorage()
    storage.create_error = StorageError("backend down")

    with pytest.raises(StorageError) as excinfo:
        _create(storage)

    assert type(excinfo.value) is StorageError
    assert excinfo.value is storage.create_error
    assert storage.audits == []


def test_audit_append_failure_propagates_with_row_persisted() -> None:
    """The documented decision-1 window: the key is committed, the audit fails,
    the error propagates (fail-closed) — never a silent success."""
    storage = StubStorage()
    storage.audit_error = StorageError("audit write failed")

    with pytest.raises(StorageError):
        _create(storage)

    # Exactly one create, then one failed append; the row persisted.
    assert storage.calls == ["create_api_key", "append_audit_event"]
    assert str(_IDS.api_key_id) in storage.keys


def test_create_audit_happens_only_after_successful_create() -> None:
    storage = StubStorage()

    _create(storage)

    # Sequencing proof for the whole flow: single write, single audit, audit
    # strictly after the write, and the literal is not a storage call argument.
    assert storage.calls == ["create_api_key", "append_audit_event"]


# ---------------------------------------------------------------------------
# Creation: determinism and default minting
# ---------------------------------------------------------------------------


def test_create_is_deterministic_under_injected_now_and_ids() -> None:
    first, second = StubStorage(), StubStorage()

    key_a, literal_a = _create(first, now=_LATER)
    key_b, literal_b = _create(second, now=_LATER)

    assert key_a.model_dump() == key_b.model_dump()
    assert literal_a == literal_b
    assert [event.model_dump() for event in first.audits] == [
        event.model_dump() for event in second.audits
    ]
    assert first.audits[0].created_at == _LATER


def test_create_without_injected_ids_mints_fresh_valid_entropy() -> None:
    storage = StubStorage()

    api_key, literal = _create(storage, now=_LATER, ids=None)

    # key_ application identity, Crockford-26 credential segment, 256-bit secret.
    assert str(api_key.id).startswith("key_")
    assert len(api_key.key_id) == KEY_ID_LENGTH
    assert set(api_key.key_id) <= set(CROCKFORD_ALPHABET)
    assert api_key.secret_hash == hash_secret(PEPPER, parse_literal(literal).secret)
    parsed = parse_literal(literal)
    assert parsed.key_id == api_key.key_id
    assert len(urlsafe_b64decode(parsed.secret + "=")) == 32
    # Minted values differ across calls (entropy, not constants).
    other_storage = StubStorage()
    other_key, _ = _create(other_storage, now=_LATER, ids=None)
    assert other_key.id != api_key.id
    assert other_key.key_id != api_key.key_id


def test_new_creation_ids_mints_complete_valid_bundle() -> None:
    minted = new_api_key_creation_ids()

    assert str(minted.api_key_id).startswith("key_")
    assert str(minted.audit_id).startswith("aud_")
    assert len(minted.key_id) == KEY_ID_LENGTH
    assert set(minted.key_id) <= set(CROCKFORD_ALPHABET)
    assert len(urlsafe_b64decode(minted.secret + "=")) == 32


def test_creation_ids_repr_redacts_the_secret() -> None:
    text = repr(_IDS) + str(_IDS)
    assert _SECRET not in text
    assert "secret=<redacted>" in text
    assert _IDS.api_key_id in text  # identities are not secret


# ---------------------------------------------------------------------------
# Revocation: happy path, duplicate CAS, tenancy, failure ordering
# ---------------------------------------------------------------------------


def test_revoke_transitions_and_audits_once_with_exact_shape() -> None:
    storage = StubStorage()
    seeded = _seed_key(storage)

    revoked = revoke_api_key(storage, _ACTOR, _ORG, seeded.id, now=_LATER)

    assert revoked.status is ApiKeyStatus.REVOKED
    assert revoked.revoked_at == _LATER
    assert storage.keys[str(seeded.id)].revoked_at == _LATER
    # Sequencing: fresh read, then CAS, then exactly one audit after the write.
    assert storage.calls == ["get_api_key", "revoke_api_key", "append_audit_event"]
    (event,) = storage.audits
    assert event.action == "api_key.revoked"
    assert event.organization_id == _ORG
    assert event.actor_type == "user"
    assert event.actor_id == _ACTOR
    assert event.target_type == "api_key"
    assert event.target_id == str(seeded.id)
    # Metadata is exactly {} (decision 10): the revoked_at truth lives on the row.
    assert event.metadata == {}
    assert event.created_at == _LATER
    assert str(event.id).startswith("aud_")


def test_duplicate_revoke_appends_exactly_one_audit_per_call() -> None:
    storage = StubStorage()
    seeded = _seed_key(storage)

    first = revoke_api_key(storage, _ACTOR, _ORG, seeded.id, now=_LATER)
    second = revoke_api_key(storage, _ACTOR, _ORG, seeded.id, now=_LATER)

    # CAS idempotent success with the original revoked_at preserved.
    assert first.revoked_at == _LATER
    assert second.revoked_at == _LATER
    assert second.status is ApiKeyStatus.REVOKED
    # Each processed call is one truthful audit row (decision 10).
    assert len(storage.audits) == 2
    assert [event.action for event in storage.audits] == ["api_key.revoked"] * 2
    assert storage.calls.count("revoke_api_key") == 2


def test_foreign_org_revoke_raises_before_any_cas_call() -> None:
    storage = StubStorage()
    seeded = _seed_key(storage, organization_id=_ORG)

    with pytest.raises(ApiKeyNotFoundError) as excinfo:
        revoke_api_key(storage, _ACTOR, _OTHER_ORG, seeded.id, now=_LATER)

    # The existence-oracle proof: no CAS call, no audit, row untouched.
    assert "revoke_api_key" not in storage.calls
    assert storage.calls == ["get_api_key"]
    assert storage.audits == []
    assert storage.keys[str(seeded.id)].status is ApiKeyStatus.ACTIVE
    # Byte-identical to the absent-key 404 (decision 10's single fixed message).
    assert str(excinfo.value) == "API key not found"


def test_unknown_key_revoke_raises_with_zero_writes() -> None:
    storage = StubStorage()

    with pytest.raises(ApiKeyNotFoundError) as excinfo:
        revoke_api_key(storage, _ACTOR, _ORG, ApiKeyId("key_" + "f" * 32), now=_LATER)

    assert str(excinfo.value) == "API key not found"
    assert storage.calls == ["get_api_key"]
    assert storage.write_calls == 0


def test_revoke_read_failure_propagates_untranslated_with_zero_writes() -> None:
    """Decision 11 on the revoke read path: only ``EntityNotFoundError`` maps to
    the 404 domain error, so any other ``StorageError`` from ``get_api_key``
    propagates untranslated (→ frozen 500) with no CAS, no audit, and no
    mutation."""
    storage = StubStorage()
    seeded = _seed_key(storage)
    storage.get_error = StorageError("backend down")

    with pytest.raises(StorageError) as excinfo:
        revoke_api_key(storage, _ACTOR, _ORG, seeded.id, now=_LATER)

    assert type(excinfo.value) is StorageError
    assert excinfo.value is storage.get_error
    assert storage.calls == ["get_api_key"]
    assert storage.write_calls == 0
    assert storage.audits == []
    assert storage.keys[str(seeded.id)].status is ApiKeyStatus.ACTIVE


def test_revoke_race_against_absence_maps_to_not_found() -> None:
    """A CAS that races deletion raises ``EntityNotFoundError`` — mapped to the
    same 404 domain error *before* any audit append."""
    storage = StubStorage()
    seeded = _seed_key(storage)
    storage.revoke_error = EntityNotFoundError("raced away")

    with pytest.raises(ApiKeyNotFoundError) as excinfo:
        revoke_api_key(storage, _ACTOR, _ORG, seeded.id, now=_LATER)

    assert isinstance(excinfo.value.__cause__, EntityNotFoundError)
    assert storage.audits == []
    assert storage.calls == ["get_api_key", "revoke_api_key"]


def test_revoke_audit_failure_propagates_after_cas() -> None:
    storage = StubStorage()
    seeded = _seed_key(storage)
    storage.audit_error = StorageError("audit write failed")

    with pytest.raises(StorageError):
        revoke_api_key(storage, _ACTOR, _ORG, seeded.id, now=_LATER)

    assert storage.calls == ["get_api_key", "revoke_api_key", "append_audit_event"]
    assert storage.keys[str(seeded.id)].status is ApiKeyStatus.REVOKED


# ---------------------------------------------------------------------------
# List: pure pass-through
# ---------------------------------------------------------------------------


def test_list_is_pass_through_preserving_page_verbatim() -> None:
    storage = StubStorage()
    seeded = _seed_key(storage)
    page = PageParams(limit=5)

    result = list_api_keys(storage, _ORG, page)

    assert storage.calls == ["list_api_keys"]
    assert isinstance(result, Page)
    assert result.items == [seeded]
    # limit echo and opaque cursor are passed through untouched (decision 8's
    # projection is router work).
    assert result.limit == 5
    assert result.next_cursor == "opaque-cursor"


def test_list_is_org_scoped_pass_through() -> None:
    storage = StubStorage()
    _seed_key(storage, api_key_id="key_" + "1" * 32)

    result = list_api_keys(storage, _OTHER_ORG, PageParams())

    assert result.items == []


def test_list_invalid_cursor_propagates_untranslated() -> None:
    storage = StubStorage()
    storage.list_error = InvalidCursorError("foreign cursor")

    with pytest.raises(InvalidCursorError):
        list_api_keys(storage, _ORG, PageParams(cursor="tampered"))


# ---------------------------------------------------------------------------
# Audit builders: pure and deterministic in isolation
# ---------------------------------------------------------------------------


def test_created_audit_builder_normalizes_scopes_and_is_pure() -> None:
    event = build_api_key_created_audit(
        audit_id=_IDS.audit_id,
        organization_id=_ORG,
        actor_user_id=_ACTOR,
        api_key_id=_IDS.api_key_id,
        environment=ApiKeyEnvironment.TEST,
        scopes=_RAW_SCOPES,
        now=_NOW,
    )
    again = build_api_key_created_audit(
        audit_id=_IDS.audit_id,
        organization_id=_ORG,
        actor_user_id=_ACTOR,
        api_key_id=_IDS.api_key_id,
        environment=ApiKeyEnvironment.TEST,
        scopes=_RAW_SCOPES,
        now=_NOW,
    )

    assert event == again
    assert event.metadata == {"environment": "test", "scopes": _SORTED_SCOPES}
    assert event.action == "api_key.created"


def test_revoked_audit_builder_carries_empty_metadata() -> None:
    event = build_api_key_revoked_audit(
        audit_id=_IDS.audit_id,
        organization_id=_ORG,
        actor_user_id=_ACTOR,
        api_key_id=_IDS.api_key_id,
        now=_LATER,
    )

    assert event.metadata == {}
    assert event.action == "api_key.revoked"
    assert event.target_id == str(_IDS.api_key_id)
    assert event.created_at == _LATER


# ---------------------------------------------------------------------------
# Domain errors: fixed messages, no credential echo
# ---------------------------------------------------------------------------


def test_domain_errors_have_fixed_input_free_messages() -> None:
    assert str(ApiKeyNotFoundError()) == "API key not found"
    assert str(ApiKeyConflictError()) == "API key id collision; retry the request"
    # A cause chain must not smuggle credential material into the message.
    with pytest.raises(ApiKeyCredentialFormatError):
        parse_literal("fn_live_bad_shape_x")
