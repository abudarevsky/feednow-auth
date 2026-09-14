"""API-key service rules and audit builders (Phase 05 task 2; spec §8/§14/§16).

Business rules behind the create/list/revoke routes, functions-with-injected-
storage like :mod:`app.services.member` (breakdown decision 0). This module
imports **no FastAPI**: HTTP translation (404/409/201/204, response schemas,
the one-crossing-point literal projection) belongs to the task-6 router, and
the access dependency enforcing admin rank is task 5's composition of the
Phase 04 seam. What lives here is the domain contract pinned by decisions
9/10:

- **Creation (decision 9):** normalize request scopes to sorted-unique
  (the Phase 02 contract defers normalization to this layer; storage then
  round-trips exactly) → mint the ``key_`` identity, the §8 ULID key-id, and
  the 256-bit secret (all injectable via :class:`ApiKeyCreationIds`) → build
  the complete :class:`~app.models.api_key.ApiKey` (``status=active``,
  ``expires_at=None`` — the frozen §15 request schema has no expiry field) →
  ``storage.create_api_key`` → append ``api_key.created`` **after** the
  successful write (the Phase 04 membership-audit ordering; the accepted
  post-commit audit window is documented in the handoff) → return
  ``(api_key, full_literal)``. The plaintext secret exists only in the
  returned literal and the injected ids; nothing here persists or logs it,
  and :meth:`ApiKeyCreationIds.__repr__` redacts it.
- **Revocation (decision 10):** ``get_api_key`` first (absence →
  :class:`ApiKeyNotFoundError`), then the tenancy check — a foreign-org key
  raises the **same** error with the **same** fixed message *before* any CAS
  call, so the revoke path is not a cross-org existence oracle — then the
  contract's first-write-wins ``revoke_api_key`` (already-revoked is an
  idempotent success preserving the original ``revoked_at``), then exactly
  one truthful ``api_key.revoked`` audit per processed call (duplicate/
  concurrent revocations each audited; winner-detection is impossible under
  same-clock ties).
- **List:** pure pass-through of the contract's org-scoped, all-statuses
  page (decision 8's projection to summaries is router work).

Audit shapes are pinned by decisions 9/10: ``api_key.created`` metadata is
exactly ``{"environment", "scopes"}`` (non-secret), ``api_key.revoked``
metadata is exactly ``{}``; both target ``api_key``/the ``key_`` identity
with the human ``usr_`` actor. Every builder is pure in injected
``ids``/``now`` — storage mints nothing, so tests stay deterministic.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from app.auth.credentials import (
    ENVIRONMENT_PREFIXES,
    build_literal,
    generate_key_id,
    generate_secret,
    hash_secret,
)
from app.models.api_key import ApiKey, ApiKeyName, Scope
from app.models.audit_event import AuditEvent
from app.models.enums import ApiKeyEnvironment, ApiKeyStatus
from app.models.ids import ApiKeyId, AuditEventId, OrganizationId, UserId
from app.models.pagination import Page, PageParams
from app.models.timestamps import utc_now
from app.services.idgen import new_api_key_id, new_audit_event_id
from app.storage.contract import (
    DuplicateEntityError,
    EntityNotFoundError,
    Storage,
)

#: Number of leading secret characters shown in ``key_prefix`` (decision 2:
#: 8 env-prefix + 26 key-id + 1 + 6 + 3 dots = 44 ≤ the frozen ≤ 64 bound;
#: the head is display-masked identification, worthless offline against the
#: peppered HMAC — see the breakdown).
KEY_PREFIX_SECRET_CHARS: Final = 6

#: Marker closing the truncated secret head inside ``key_prefix``.
KEY_PREFIX_ELLIPSIS: Final = "..."


# ---------------------------------------------------------------------------
# Service domain errors (decision 11 — routers own the HTTP translation)
# ---------------------------------------------------------------------------


class ApiKeyNotFoundError(Exception):
    """No key with that ``key_`` identity exists **in this organization** (404).

    The single fixed message covers both the absent key and the foreign-org
    key (decision 10): revocation must never reveal whether a key exists in
    another organization, so the two cases are indistinguishable at this
    boundary and the router renders one byte-identical 404 envelope.
    """

    def __init__(self, message: str = "API key not found") -> None:
        super().__init__(message)


class ApiKeyConflictError(Exception):
    """The freshly minted credential collided with a storage uniqueness
    constraint (409; decision 11).

    Covers both ``kind="api_key_id"`` (ULID segment) and ``kind="entity_id"``
    (``key_`` record id) duplicates raised by ``create_api_key`` — the UNIQUE
    index is the arbiter, creation is non-idempotent by design, and the
    correct client behavior is a plain retry that mints fresh entropy. The
    message is fixed and echoes nothing.
    """

    def __init__(self, message: str = "API key id collision; retry the request") -> None:
        super().__init__(message)


# ---------------------------------------------------------------------------
# Injectable entropy (decision 9: "injectable storage/now/pepper/ids")
# ---------------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class ApiKeyCreationIds:
    """Every entropy value one creation mints: identities plus §8 segments.

    ``api_key_id`` is the ``key_`` application identity and ``audit_id`` the
    ``api_key.created`` record id; ``key_id``/``secret`` are the credential
    segments from :mod:`app.auth.credentials`. ``secret`` is plaintext
    credential material, so ``repr``/``str`` are redacted (AGENTS.md: no
    plaintext secret may reach logs, and a stray dump or exception context
    must not carry it).
    """

    api_key_id: ApiKeyId
    audit_id: AuditEventId
    key_id: str
    secret: str

    def __repr__(self) -> str:
        return (
            f"ApiKeyCreationIds(api_key_id={self.api_key_id!r}, "
            f"audit_id={self.audit_id!r}, key_id={self.key_id!r}, secret=<redacted>)"
        )

    __str__ = __repr__


def new_api_key_creation_ids() -> ApiKeyCreationIds:
    """Mint the complete id bundle for one creation (application ids plus the
    credential segment and 256-bit secret; decision 2's generators)."""
    return ApiKeyCreationIds(
        api_key_id=new_api_key_id(),
        audit_id=new_audit_event_id(),
        key_id=generate_key_id(),
        secret=generate_secret(),
    )


# ---------------------------------------------------------------------------
# Pure rules
# ---------------------------------------------------------------------------


def normalize_scopes(scopes: Sequence[Scope]) -> list[str]:
    """Return the scopes **sorted and de-duplicated** (decision 9).

    The Phase 02 contract round-trips scope lists verbatim and defers
    normalization to this layer; calling it once before the build means the
    persisted row and the ``api_key.created`` audit carry the identical
    canonical list. Shape validation stays with the frozen ``Scope`` type
    (schemas are the single validator; decision 11).
    """
    return sorted(set(scopes))


def build_key_prefix(environment: ApiKeyEnvironment, key_id: str, secret: str) -> str:
    """Assemble the display prefix pinned by decision 2.

    ``fn_<env>_<key-id>_<first 6 secret chars>...`` — the key-id segment is
    non-secret by §8 design and the 6-char head is standard masked
    identification (Stripe/GitHub precedent); the full secret never appears.
    """
    head = secret[:KEY_PREFIX_SECRET_CHARS]
    return f"{ENVIRONMENT_PREFIXES[environment]}{key_id}_{head}{KEY_PREFIX_ELLIPSIS}"


# ---------------------------------------------------------------------------
# Audit-event builders (decisions 9/10 — pure in injected ids/now)
# ---------------------------------------------------------------------------


def build_api_key_created_audit(
    *,
    audit_id: AuditEventId,
    organization_id: OrganizationId,
    actor_user_id: UserId,
    api_key_id: ApiKeyId,
    environment: ApiKeyEnvironment,
    scopes: Sequence[Scope],
    now: datetime,
) -> AuditEvent:
    """``api_key.created`` — metadata exactly ``{"environment", "scopes"}``
    (decision 9): the environment string and the sorted-unique scope list,
    both non-secret. Target is ``api_key``/the ``key_`` application identity;
    actor is the human creator ``usr_``. The secret, hash, prefix, and
    credential segment never enter the event."""
    return AuditEvent(
        id=audit_id,
        organization_id=organization_id,
        actor_type="user",
        actor_id=actor_user_id,
        action="api_key.created",
        target_type="api_key",
        target_id=str(api_key_id),
        metadata={"environment": environment.value, "scopes": normalize_scopes(scopes)},
        created_at=now,
    )


def build_api_key_revoked_audit(
    *,
    audit_id: AuditEventId,
    organization_id: OrganizationId,
    actor_user_id: UserId,
    api_key_id: ApiKeyId,
    now: datetime,
) -> AuditEvent:
    """``api_key.revoked`` — metadata exactly ``{}`` (decision 10): the action
    and target are the whole record; the ``revoked_at`` truth lives on the
    key row, not in audit. Target ``api_key``/the ``key_`` id, actor the human
    ``usr_``. ``append_audit_event``'s docstring names this event as its
    intended Phase 05 standalone user."""
    return AuditEvent(
        id=audit_id,
        organization_id=organization_id,
        actor_type="user",
        actor_id=actor_user_id,
        action="api_key.revoked",
        target_type="api_key",
        target_id=str(api_key_id),
        metadata={},
        created_at=now,
    )


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


def create_api_key(
    storage: Storage,
    actor_user_id: UserId,
    organization_id: OrganizationId,
    name: ApiKeyName,
    environment: ApiKeyEnvironment,
    scopes: Sequence[Scope],
    *,
    pepper: bytes,
    now: datetime | None = None,
    ids: ApiKeyCreationIds | None = None,
) -> tuple[ApiKey, str]:
    """Create one API key and return ``(stored_key, full_literal)`` exactly once.

    Fixed order (decision 9): normalize scopes → mint (or accept injected)
    ids/secret → build the complete :class:`ApiKey` with
    ``secret_hash = HMAC-SHA256(pepper, secret)`` (lowercase hex, decision 2)
    → ``storage.create_api_key`` → ``api_key.created`` audit **after** the
    successful write → assemble the literal from the stored (unchanged,
    caller-echo contract) segments plus the minted secret.

    A storage failure means zero writes: the create error propagates (mapped
    per decision 11) before any audit append is attempted, and an audit-append
    failure propagates uncaught (fail-closed; the persisted-key/lost-plaintext
    window is the documented decision-1 limitation). ``now``/``ids`` are
    injectable; production reads the clock once per creation.

    Raises:
        ApiKeyConflictError: ULID-segment or record-id collision (router → 409).
    """
    minted = ids if ids is not None else new_api_key_creation_ids()
    timestamp = now if now is not None else utc_now()
    api_key = ApiKey(
        id=minted.api_key_id,
        organization_id=organization_id,
        created_by_user_id=actor_user_id,
        name=name,
        key_id=minted.key_id,
        key_prefix=build_key_prefix(environment, minted.key_id, minted.secret),
        secret_hash=hash_secret(pepper, minted.secret),
        environment=environment,
        scopes=normalize_scopes(scopes),
        status=ApiKeyStatus.ACTIVE,
        created_at=timestamp,
        expires_at=None,
    )
    try:
        stored = storage.create_api_key(api_key)
    except DuplicateEntityError as exc:
        raise ApiKeyConflictError() from exc
    storage.append_audit_event(
        build_api_key_created_audit(
            audit_id=minted.audit_id,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            api_key_id=stored.id,
            environment=stored.environment,
            scopes=stored.scopes,
            now=timestamp,
        )
    )
    literal = build_literal(stored.environment, stored.key_id, minted.secret)
    return stored, literal


def revoke_api_key(
    storage: Storage,
    actor_user_id: UserId,
    organization_id: OrganizationId,
    api_key_id: ApiKeyId,
    *,
    now: datetime | None = None,
) -> ApiKey:
    """Revoke one org-scoped key (idempotent CAS) and audit the processed call.

    Fixed order (decision 10): ``get_api_key`` → tenancy check → CAS →
    exactly one ``api_key.revoked`` audit **after** the successful transition.
    The foreign-org branch raises :class:`ApiKeyNotFoundError` *before*
    ``storage.revoke_api_key`` is ever called — the recording-stub test pins
    that no CAS runs, so a probe cannot learn whether the key exists and only
    the 404-vs-404 shape is observable. An already-revoked (or concurrently
    revoked) key is an idempotent success: the contract's CAS returns the
    stored row with the **original** ``revoked_at`` preserved, and each
    processed call appends its own truthful audit row (duplicate semantics
    defined and tested per AGENTS.md). "Immediately effective" is structural:
    verification reads stored truth per request, so the next call sees
    ``status=revoked``.

    Returns the stored post-CAS key (the router discards it for the
    manifest-pinned 204; tests assert the preserved ``revoked_at``).

    Raises:
        ApiKeyNotFoundError: unknown id, foreign-org id, or a race against
            absence — one indistinguishable 404 (decision 10).
    """
    timestamp = now if now is not None else utc_now()
    try:
        api_key = storage.get_api_key(api_key_id)
    except EntityNotFoundError as exc:
        raise ApiKeyNotFoundError() from exc
    if api_key.organization_id != organization_id:
        # Same error, same fixed message, raised before any CAS call: no
        # cross-org existence oracle.
        raise ApiKeyNotFoundError()
    try:
        revoked = storage.revoke_api_key(api_key_id, revoked_at=timestamp)
    except EntityNotFoundError as exc:
        raise ApiKeyNotFoundError() from exc
    storage.append_audit_event(
        build_api_key_revoked_audit(
            audit_id=new_audit_event_id(),
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            api_key_id=revoked.id,
            now=timestamp,
        )
    )
    return revoked


def list_api_keys(
    storage: Storage,
    organization_id: OrganizationId,
    page: PageParams,
) -> Page[ApiKey]:
    """Pass-through of the contract's org-scoped, all-statuses key page.

    No filtering, reordering, or cursor interpretation is invented here (the
    contract pins ``(created_at, id)`` order and opaque cursors; the router
    projects field-by-field to summaries preserving ``limit``/``next_cursor``
    verbatim — Phase 04 decision-8 pattern).
    """
    return storage.list_api_keys(organization_id, page)


__all__ = [
    "KEY_PREFIX_ELLIPSIS",
    "KEY_PREFIX_SECRET_CHARS",
    "ApiKeyConflictError",
    "ApiKeyCreationIds",
    "ApiKeyNotFoundError",
    "build_api_key_created_audit",
    "build_api_key_revoked_audit",
    "build_key_prefix",
    "create_api_key",
    "list_api_keys",
    "new_api_key_creation_ids",
    "normalize_scopes",
    "revoke_api_key",
]
