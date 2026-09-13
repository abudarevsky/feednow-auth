"""SQLite adapter core: schema, connections, codecs, and mappers (Phase 02 task 2).

This module owns everything SQLite-specific in the application. Nothing here
may leak above the adapter: the contract operations added by tasks 3-7
translate ``sqlite3`` errors into the domain vocabulary in
:mod:`app.storage.contract`, and application code is typed only against that
contract and reaches this adapter through :func:`open_sqlite_storage`.

Design pinned by the Phase 02 breakdown:

- **Stdlib only.** ``sqlite3`` is the single driver; no ORM (SQLAlchemy is a
  spec §11 leak example).
- **Connection model.** Thread-local connections, ``journal_mode=WAL``,
  ``busy_timeout`` 5 s, and ``foreign_keys`` enforced as the *first*
  statements after ``connect()`` on every connection (``PRAGMA foreign_keys``
  is a silent no-op inside an open transaction, so it must run before any
  other SQL; init asserts the read-back is ``1``). Schema creation is
  idempotent and stamped with ``PRAGMA user_version``.
- **Storage never mints IDs or timestamps.** Every write receives a fully
  formed domain entity; the codecs below only encode/decode what callers
  supply.
- **Sortable timestamps.** Timestamp columns store TEXT
  ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` — fixed-width, microseconds always present
  — so lexicographic order equals chronological order, which keyset
  pagination relies on. ``to_utc_rfc3339`` omits zero-microsecond fields and
  must **not** be reused for stored columns. Read back with
  ``datetime.fromisoformat`` (accepts ``Z`` since 3.11).
- **Tenant normalization.** ``provider_tenant=None`` is stored as the
  normalized empty string ``''`` (SQLite ``UNIQUE`` treats NULLs as distinct,
  which would let duplicate identities slip through) and mapped back to
  ``None`` on read; the mapping is lossless because ``ProviderTenant`` pins
  ``min_length=1``.
- **Opaque cursors.** Keyset cursors are base64url JSON carrying the
  position ``(created_at, id)`` *plus a list-scope tag* so a cursor issued
  for one list is invalid for another. They are created/decoded only inside
  this module; malformed, tampered, or foreign tokens raise
  :class:`~app.storage.contract.InvalidCursorError`, never ``ValueError`` or
  a driver error.
- **Corrupt stored values fail loudly.** Row→domain reconstruction goes
  through ``model_validate``, so a bad enum string or ID prefix raises
  (documented tripwire, not silent coercion).

Task boundary: task 3 implemented the users/external-identity operations
(:meth:`SQLiteStorage.create_user`, :meth:`SQLiteStorage.get_user`,
:meth:`SQLiteStorage.create_external_identity`,
:meth:`SQLiteStorage.get_user_by_external_identity`) with the sqlite3→domain
error translation below; task 4 added the organization and membership
operations (:meth:`SQLiteStorage.create_organization`,
:meth:`SQLiteStorage.get_organization`,
:meth:`SQLiteStorage.list_user_organizations`,
:meth:`SQLiteStorage.create_membership`, :meth:`SQLiteStorage.get_membership`,
:meth:`SQLiteStorage.list_memberships`,
:meth:`SQLiteStorage.delete_membership`) on top of the keyset-pagination
helper; task 5 added the API-key operations
(:meth:`SQLiteStorage.create_api_key`, :meth:`SQLiteStorage.get_api_key`,
:meth:`SQLiteStorage.get_api_key_by_key_id`,
:meth:`SQLiteStorage.list_api_keys`, :meth:`SQLiteStorage.revoke_api_key`)
including the first-write-wins revocation CAS; task 6 added the standalone
audit write (:meth:`SQLiteStorage.append_audit_event`) on the shared
``_insert_audit_event_row`` helper; task 7 completed the contract surface with
the :meth:`SQLiteStorage.provision_user` atomic compound — a single-transaction
batch write (``BEGIN IMMEDIATE``) over the shared row-insert helpers the
standalone ``create_*`` methods now delegate to, with the spec §6
race-error mapping pinned in the contract. Phase 04 task 1 added the second
compound, :meth:`SQLiteStorage.provision_organization` (organization +
membership + audits in one transaction, deliberately **no** race-convergence
mapping — a slug conflict is a plain translated ``DuplicateEntityError``).
Behavior/conformance testing is owned by ``src/tests/storage_contract/``.
"""

from __future__ import annotations

import base64
import binascii
import json
import sqlite3
import threading
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from app.models.api_key import ApiKey, KeyId
from app.models.audit_event import AuditEvent
from app.models.enums import ApiKeyStatus, IdentityProvider, MembershipStatus
from app.models.external_identity import ExternalIdentity, ProviderTenant
from app.models.ids import ApiKeyId, OrganizationId, ProviderSubject, UserId
from app.models.membership import Membership
from app.models.organization import Organization
from app.models.pagination import Page, PageParams, clamp_limit
from app.models.timestamps import UtcDatetime, ensure_utc
from app.models.user import User
from app.storage.contract import (
    DuplicateEntityError,
    DuplicateEntityKind,
    DuplicateExternalIdentityError,
    EntityNotFoundError,
    InvalidCursorError,
    ProvisionedOrganization,
    ProvisionedUser,
    ReferenceNotFoundError,
    Storage,
    StorageError,
)

#: Schema version stamped into ``PRAGMA user_version`` after creation. Bump
#: only with a spec-revision-approved migration story; an unrecognized stamp
#: is rejected loudly rather than reinterpreted.
SCHEMA_VERSION: Final = 1

#: Wall-clock bound (ms) for lock contention under WAL, per the breakdown's
#: connection model (concurrency tests use barriers + WAL, never sleeps).
_BUSY_TIMEOUT_MS: Final = 5000

# ---------------------------------------------------------------------------
# DDL: six tables, PKs, FKs, and the five unique indexes (four domain
# uniqueness constraints plus the §8 api_keys.key_id credential segment).
# ---------------------------------------------------------------------------

_SCHEMA_STATEMENTS: Final[tuple[str, ...]] = (
    """
    CREATE TABLE IF NOT EXISTS users (
        id           TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        email        TEXT NOT NULL,
        status       TEXT NOT NULL,
        created_at   TEXT NOT NULL,
        updated_at   TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (email)",
    """
    CREATE TABLE IF NOT EXISTS external_identities (
        id               TEXT PRIMARY KEY,
        user_id          TEXT NOT NULL REFERENCES users (id),
        provider         TEXT NOT NULL,
        provider_subject TEXT NOT NULL,
        provider_tenant  TEXT NOT NULL,
        created_at       TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS external_identities_tuple_unique "
    "ON external_identities (provider, provider_subject, provider_tenant)",
    """
    CREATE TABLE IF NOT EXISTS organizations (
        id         TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        slug       TEXT NOT NULL,
        type       TEXT NOT NULL,
        status     TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS organizations_slug_unique ON organizations (slug)",
    """
    CREATE TABLE IF NOT EXISTS memberships (
        id              TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL REFERENCES organizations (id),
        user_id         TEXT NOT NULL REFERENCES users (id),
        role            TEXT NOT NULL,
        status          TEXT NOT NULL,
        created_at      TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS memberships_pair_unique "
    "ON memberships (organization_id, user_id)",
    """
    CREATE TABLE IF NOT EXISTS api_keys (
        id                 TEXT PRIMARY KEY,
        organization_id    TEXT NOT NULL REFERENCES organizations (id),
        created_by_user_id TEXT NOT NULL REFERENCES users (id),
        name               TEXT NOT NULL,
        key_id             TEXT NOT NULL,
        key_prefix         TEXT NOT NULL,
        secret_hash        TEXT NOT NULL,
        environment        TEXT NOT NULL,
        scopes             TEXT NOT NULL,
        status             TEXT NOT NULL,
        created_at         TEXT NOT NULL,
        last_used_at       TEXT,
        expires_at         TEXT,
        revoked_at         TEXT
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS api_keys_key_id_unique ON api_keys (key_id)",
    """
    CREATE TABLE IF NOT EXISTS audit_events (
        id              TEXT PRIMARY KEY,
        organization_id TEXT NOT NULL REFERENCES organizations (id),
        actor_type      TEXT NOT NULL,
        actor_id        TEXT NOT NULL,
        action          TEXT NOT NULL,
        target_type     TEXT,
        target_id       TEXT,
        metadata        TEXT NOT NULL,
        created_at      TEXT NOT NULL
    )
    """,
)

#: Tables the schema owns (documentation and conformance-facing inventory).
TABLE_NAMES: Final[tuple[str, ...]] = (
    "users",
    "external_identities",
    "organizations",
    "memberships",
    "api_keys",
    "audit_events",
)

#: Unique index inventory (five: four domain-uniqueness constraints plus the
#: §8 credential-segment point lookup).
UNIQUE_INDEX_NAMES: Final[tuple[str, ...]] = (
    "users_email_unique",
    "external_identities_tuple_unique",
    "organizations_slug_unique",
    "memberships_pair_unique",
    "api_keys_key_id_unique",
)

# ---------------------------------------------------------------------------
# List-scope tags embedded in keyset cursors (contract: a cursor from one
# list is invalid for another).
# ---------------------------------------------------------------------------

CURSOR_SCOPE_USER_ORGANIZATIONS: Final = "user_organizations"
CURSOR_SCOPE_MEMBERSHIPS: Final = "memberships"
CURSOR_SCOPE_API_KEYS: Final = "api_keys"

# ---------------------------------------------------------------------------
# Codecs (pure helpers; unit-tested in tests/unit/test_sqlite_core.py)
# ---------------------------------------------------------------------------


def encode_timestamp(value: datetime) -> str:
    """Encode an aware datetime as the fixed-width sortable UTC TEXT form.

    ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` — microseconds are always present so
    lexicographic order equals chronological order. Naive datetimes are
    rejected (:func:`~app.models.timestamps.ensure_utc` raises ``ValueError``).
    """
    normalized = ensure_utc(value)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def decode_timestamp(text: str) -> datetime:
    """Decode a stored timestamp back to an aware UTC datetime.

    Raises ``ValueError`` for malformed or naive stored text — a corrupt row
    must fail loudly, not coerce (contract tripwire).
    """
    return ensure_utc(datetime.fromisoformat(text))


def encode_provider_tenant(value: ProviderTenant | None) -> str:
    """Normalize an optional tenant for storage: ``None`` becomes ``''``.

    ``''`` can never be a legitimate domain value (``ProviderTenant`` pins
    ``min_length=1``), so the mapping is lossless and keeps the identity
    uniqueness tuple NULL-free (SQLite treats NULLs as distinct in UNIQUE).
    """
    return "" if value is None else value


def decode_provider_tenant(value: str) -> ProviderTenant | None:
    """Inverse of :func:`encode_provider_tenant` (``''`` reads back as ``None``)."""
    return value or None


def encode_json_column(value: object) -> str:
    """Encode a JSON-safe value (scope array, audit metadata) as compact TEXT.

    Key order and array order are preserved exactly — no ``sort_keys`` — so
    ``scopes`` round-trip with duplicates and order intact (normalization is
    Phase 05 domain work).
    """
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def decode_json_column(text: str) -> Any:
    """Decode a JSON TEXT column; malformed stored data raises ``ValueError``."""
    return json.loads(text)


def encode_cursor(scope: str, created_at: datetime, entity_id: str) -> str:
    """Encode an opaque keyset cursor for one list scope.

    The payload carries the ``(created_at, id)`` position *and* the list-scope
    tag so a cursor issued for one list is invalid for another. The result is
    unpadded base64url text: callers must treat it as an opaque string and
    never parse it (only this module decodes).
    """
    payload = {
        "scope": scope,
        "created_at": encode_timestamp(created_at),
        "id": entity_id,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(scope: str, cursor: str) -> tuple[datetime, str]:
    """Decode a cursor and pin it to the expected list ``scope``.

    Returns the ``(created_at, id)`` position key. Any malformed, tampered,
    or foreign-scope token raises :class:`InvalidCursorError` — never a raw
    ``ValueError``, ``binascii.Error``, or driver error.
    """
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise InvalidCursorError("cursor could not be decoded") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"scope", "created_at", "id"}
        or not isinstance(payload["scope"], str)
        or not isinstance(payload["created_at"], str)
        or not isinstance(payload["id"], str)
    ):
        raise InvalidCursorError("cursor payload is malformed")
    if payload["scope"] != scope:
        raise InvalidCursorError("cursor was issued for a different list")
    try:
        created_at = decode_timestamp(payload["created_at"])
    except ValueError as exc:
        raise InvalidCursorError("cursor position is malformed") from exc
    return created_at, payload["id"]


# ---------------------------------------------------------------------------
# Row → domain mappers. Column names mirror the domain field names exactly;
# reconstruction goes through ``model_validate`` so corrupt stored values
# (bad enum strings, wrong ID prefixes) fail loudly.
# ---------------------------------------------------------------------------


def user_from_row(row: sqlite3.Row) -> User:
    """Rebuild a :class:`User` from a ``users`` row."""
    return User.model_validate(
        {
            "id": row["id"],
            "display_name": row["display_name"],
            "email": row["email"],
            "status": row["status"],
            "created_at": decode_timestamp(row["created_at"]),
            "updated_at": decode_timestamp(row["updated_at"]),
        }
    )


def external_identity_from_row(row: sqlite3.Row) -> ExternalIdentity:
    """Rebuild an :class:`ExternalIdentity` from an ``external_identities`` row."""
    return ExternalIdentity.model_validate(
        {
            "id": row["id"],
            "user_id": row["user_id"],
            "provider": row["provider"],
            "provider_subject": row["provider_subject"],
            "provider_tenant": decode_provider_tenant(row["provider_tenant"]),
            "created_at": decode_timestamp(row["created_at"]),
        }
    )


def organization_from_row(row: sqlite3.Row) -> Organization:
    """Rebuild an :class:`Organization` from an ``organizations`` row."""
    return Organization.model_validate(
        {
            "id": row["id"],
            "name": row["name"],
            "slug": row["slug"],
            "type": row["type"],
            "status": row["status"],
            "created_at": decode_timestamp(row["created_at"]),
            "updated_at": decode_timestamp(row["updated_at"]),
        }
    )


def membership_from_row(row: sqlite3.Row) -> Membership:
    """Rebuild a :class:`Membership` from a ``memberships`` row."""
    return Membership.model_validate(
        {
            "id": row["id"],
            "organization_id": row["organization_id"],
            "user_id": row["user_id"],
            "role": row["role"],
            "status": row["status"],
            "created_at": decode_timestamp(row["created_at"]),
        }
    )


def api_key_from_row(row: sqlite3.Row) -> ApiKey:
    """Rebuild an :class:`ApiKey` from an ``api_keys`` row (scopes via the JSON codec)."""
    return ApiKey.model_validate(
        {
            "id": row["id"],
            "organization_id": row["organization_id"],
            "created_by_user_id": row["created_by_user_id"],
            "name": row["name"],
            "key_id": row["key_id"],
            "key_prefix": row["key_prefix"],
            "secret_hash": row["secret_hash"],
            "environment": row["environment"],
            "scopes": decode_json_column(row["scopes"]),
            "status": row["status"],
            "created_at": decode_timestamp(row["created_at"]),
            "last_used_at": None
            if row["last_used_at"] is None
            else decode_timestamp(row["last_used_at"]),
            "expires_at": None
            if row["expires_at"] is None
            else decode_timestamp(row["expires_at"]),
            "revoked_at": None
            if row["revoked_at"] is None
            else decode_timestamp(row["revoked_at"]),
        }
    )


def audit_event_from_row(row: sqlite3.Row) -> AuditEvent:
    """Rebuild an :class:`AuditEvent` from an ``audit_events`` row (metadata via JSON)."""
    return AuditEvent.model_validate(
        {
            "id": row["id"],
            "organization_id": row["organization_id"],
            "actor_type": row["actor_type"],
            "actor_id": row["actor_id"],
            "action": row["action"],
            "target_type": row["target_type"],
            "target_id": row["target_id"],
            "metadata": decode_json_column(row["metadata"]),
            "created_at": decode_timestamp(row["created_at"]),
        }
    )


# ---------------------------------------------------------------------------
# sqlite3 → domain error translation (acceptance 1: no driver exception and
# no SQL constraint text may escape the adapter; callers branch on the
# domain types from app.storage.contract instead).
# ---------------------------------------------------------------------------

#: Maps every unique constraint the task-2 DDL declares to its domain
#: ``kind``. Keys are ``(table, columns)`` exactly as SQLite reports them in
#: ``UNIQUE constraint failed: <table>.<column>[, ...]`` messages — the five
#: named unique indexes plus the six implicit PRIMARY KEY indexes (a ``id``
#: collision reports the same way and surfaces as ``entity_id``, per the
#: contract). Tasks 4-6 reuse this table as their methods land; a violation
#: of an unmapped constraint falls through to the generic ``StorageError``
#: (fail loudly, never leak the driver error).
_UNIQUE_KIND_BY_COLUMNS: Final[dict[tuple[str, tuple[str, ...]], DuplicateEntityKind]] = {
    ("api_keys", ("id",)): DuplicateEntityKind.ENTITY_ID,
    ("api_keys", ("key_id",)): DuplicateEntityKind.API_KEY_ID,
    ("audit_events", ("id",)): DuplicateEntityKind.ENTITY_ID,
    ("external_identities", ("id",)): DuplicateEntityKind.ENTITY_ID,
    (
        "external_identities",
        ("provider", "provider_subject", "provider_tenant"),
    ): DuplicateEntityKind.EXTERNAL_IDENTITY,
    ("memberships", ("id",)): DuplicateEntityKind.ENTITY_ID,
    ("memberships", ("organization_id", "user_id")): DuplicateEntityKind.MEMBERSHIP,
    ("organizations", ("id",)): DuplicateEntityKind.ENTITY_ID,
    ("organizations", ("slug",)): DuplicateEntityKind.ORGANIZATION_SLUG,
    ("users", ("id",)): DuplicateEntityKind.ENTITY_ID,
    ("users", ("email",)): DuplicateEntityKind.USER_EMAIL,
}


def _parse_unique_constraint(message: str) -> tuple[str, tuple[str, ...]] | None:
    """Extract ``(table, columns)`` from a UNIQUE-failure message, if shaped.

    Returns ``None`` for anything that is not a single-table, fully qualified
    ``UNIQUE constraint failed: t.a, t.b`` message, so an unexpected driver
    text can never be misread as a known domain conflict.
    """
    prefix = "UNIQUE constraint failed:"
    if not message.startswith(prefix):
        return None
    parts = [part.strip() for part in message[len(prefix) :].split(",")]
    if not parts or any("." not in part for part in parts):
        return None
    tables = {part.split(".", 1)[0] for part in parts}
    if len(tables) != 1:
        return None
    columns = tuple(part.split(".", 1)[1] for part in parts)
    return tables.pop(), columns


def _translate_integrity_error(exc: sqlite3.IntegrityError) -> StorageError:
    """Translate a driver integrity error into the domain vocabulary.

    Never raises and never returns driver text: the caller raises the
    returned :class:`~app.storage.contract.StorageError` subclass. Foreign
    key failures become :class:`~app.storage.contract.ReferenceNotFoundError`,
    mapped unique/PK violations become
    :class:`~app.storage.contract.DuplicateEntityError` with the pinned
    ``kind``, and anything unrecognized becomes the generic
    :class:`~app.storage.contract.StorageError`.
    """
    message = str(exc)
    errorname: str = getattr(exc, "sqlite_errorname", "")
    if errorname == "SQLITE_CONSTRAINT_FOREIGNKEY" or message.startswith("FOREIGN KEY"):
        return ReferenceNotFoundError("a referenced parent record does not exist")
    parsed = _parse_unique_constraint(message)
    if parsed is not None:
        kind = _UNIQUE_KIND_BY_COLUMNS.get(parsed)
        if kind is not None:
            return DuplicateEntityError(kind)
    return StorageError("storage write violated an integrity constraint")


def _translate_driver_error(exc: sqlite3.Error) -> StorageError:
    """Map *any* driver error to the domain vocabulary (contract: no
    ``sqlite3`` exception may propagate above the adapter). Integrity
    failures get the precise per-constraint translation; everything else
    (``OperationalError`` lock timeouts, disk faults, ...) becomes the
    generic :class:`~app.storage.contract.StorageError` with no driver text.
    """
    if isinstance(exc, sqlite3.IntegrityError):
        return _translate_integrity_error(exc)
    return StorageError("storage write failed")


# ---------------------------------------------------------------------------
# Keyset pagination helper (shared by the list_* contract methods). Callers
# fetch ``limit + 1`` rows; this trims the probe row, decides ``next_cursor``,
# and encodes the cursor from the position key of the last *returned* item.
# The ``position`` callable extracts ``(created_at, id)`` from a domain
# object so the helper stays type-safe without exposing rows upward.
# ---------------------------------------------------------------------------


def _build_page[T](
    mapped: Sequence[T],
    *,
    scope: str,
    limit: int,
    position: Callable[[T], tuple[datetime, str]],
) -> Page[T]:
    """Turn a ``limit + 1`` fetch of mapped domain objects into a Page."""
    has_more = len(mapped) > limit
    items = list(mapped[:limit])
    next_cursor: str | None = None
    if has_more and items:
        created_at, entity_id = position(items[-1])
        next_cursor = encode_cursor(scope, created_at, entity_id)
    return Page(items=items, limit=limit, next_cursor=next_cursor)


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class SQLiteStorage:
    """SQLite-backed :class:`~app.storage.contract.Storage` adapter.

    Construct through :func:`open_sqlite_storage` (the documented factory);
    application code is typed against the ``Storage`` protocol only.

    Connections are thread-local: each using thread opens its own connection
    with the driver PRAGMAs applied as the first statements, and the schema
    is created exactly once per file (idempotent, ``user_version``-stamped).
    ``close()`` releases every connection this instance opened; the instance
    is not reusable afterwards (reuse raises :class:`StorageError`).

    Connections are opened with ``check_same_thread=False`` because the
    thread-local discipline here never shares a connection across threads
    concurrently: a connection is created by, used by, and closed by exactly
    one owner; ``close()`` runs after joining worker threads (teardown, not
    concurrent use).
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._local = threading.local()
        self._connections: list[sqlite3.Connection] = []
        self._lock = threading.Lock()
        self._schema_ready = False
        self._closed = False
        # Fail fast on an unusable file/version by initializing on the
        # opening thread.
        self._ensure_schema(self._connection())

    @property
    def path(self) -> Path:
        """Filesystem location of the database this adapter manages."""
        return self._path

    # -- connection management ---------------------------------------------

    def _open_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        # Driver discipline first: these PRAGMAs are the very first statements
        # on every connection, before any other SQL. ``foreign_keys`` is a
        # silent no-op inside an open transaction, so it must run before any
        # DML could start one — and the read-back assertion proves it stuck.
        conn.execute("PRAGMA foreign_keys = ON")
        # busy_timeout before the WAL conversion: switching journal modes
        # takes an exclusive lock, so the contention bound must already be in
        # effect when a second process initializes the same file.
        conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA journal_mode = WAL")
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            conn.close()
            raise StorageError("SQLite foreign-key enforcement could not be enabled")
        conn.row_factory = sqlite3.Row
        return conn

    def _connection(self) -> sqlite3.Connection:
        """Return this thread's connection, opening (and initializing) one if needed."""
        if self._closed:
            raise StorageError("this storage adapter instance is closed")
        conn: sqlite3.Connection | None = getattr(self._local, "connection", None)
        if conn is None:
            conn = self._open_connection()
            self._local.connection = conn
            with self._lock:
                self._connections.append(conn)
            self._ensure_schema(conn)
        return conn

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        """Create the schema once per file; idempotent and version-stamped."""
        with self._lock:
            if self._schema_ready:
                return
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, SCHEMA_VERSION):
                raise StorageError(
                    f"unsupported schema version {version} at {self._path}; "
                    f"expected {SCHEMA_VERSION}"
                )
            if version == 0:
                for statement in _SCHEMA_STATEMENTS:
                    conn.execute(statement)
                conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                conn.commit()
            self._schema_ready = True

    def close(self) -> None:
        """Release every connection opened by this instance. Not reusable after."""
        with self._lock:
            self._closed = True
            for conn in self._connections:
                conn.close()
            self._connections.clear()
        self._schema_ready = False

    # -- Users and external identities (task 3) ------------------------------

    def _insert_user_row(self, conn: sqlite3.Connection, user: User) -> None:
        """Insert one user row inside the **caller's** transaction.

        Shared by :meth:`create_user` (standalone path) and
        :meth:`provision_user` (batch, task 7): the helper never commits or
        rolls back — transaction discipline belongs to the calling contract
        method. Storage mints nothing: the row is exactly the caller-supplied
        entity, with both temporal columns through the fixed-width codec.
        """
        conn.execute(
            "INSERT INTO users (id, display_name, email, status, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(user.id),
                user.display_name,
                user.email,
                str(user.status),
                encode_timestamp(user.created_at),
                encode_timestamp(user.updated_at),
            ),
        )

    def create_user(self, user: User) -> User:
        """Persist a new user and echo the caller-supplied entity back.

        Storage mints nothing: the row is exactly ``user``. Duplicate emails
        and ``usr_`` id collisions surface as translated
        :class:`~app.storage.contract.DuplicateEntityError` kinds
        (``user_email`` / ``entity_id``); the failed transaction is rolled
        back so the rejected write leaves no trace.
        """
        conn = self._connection()
        try:
            self._insert_user_row(conn, user)
        except sqlite3.Error as exc:
            # Covers IntegrityError (translated per constraint) and every
            # other driver failure (lock timeout, disk fault): roll the
            # implicit transaction back so the thread-local connection is
            # never left stale, and raise only domain errors (contract:
            # sqlite3 exceptions must not escape the adapter).
            conn.rollback()
            raise _translate_driver_error(exc) from exc
        conn.commit()
        return user

    def get_user(self, user_id: UserId) -> User:
        """Load a user by ``usr_`` identity; a miss raises ``EntityNotFoundError``."""
        conn = self._connection()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (str(user_id),)).fetchone()
        if row is None:
            raise EntityNotFoundError(f"no user with id {user_id!r}")
        return user_from_row(row)

    def _insert_external_identity_row(
        self,
        conn: sqlite3.Connection,
        identity: ExternalIdentity,
    ) -> None:
        """Insert one external-identity row inside the **caller's** transaction.

        Shared by :meth:`create_external_identity` and :meth:`provision_user`;
        the tenant goes through :func:`encode_provider_tenant` so ``None``
        participates in the uniqueness tuple as ``''``.
        """
        conn.execute(
            "INSERT INTO external_identities"
            " (id, user_id, provider, provider_subject, provider_tenant, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(identity.id),
                str(identity.user_id),
                str(identity.provider),
                identity.provider_subject,
                encode_provider_tenant(identity.provider_tenant),
                encode_timestamp(identity.created_at),
            ),
        )

    def create_external_identity(self, identity: ExternalIdentity) -> ExternalIdentity:
        """Attach a provider identity to an existing user (caller-echo).

        The tenant is stored through :func:`encode_provider_tenant` so
        ``None`` participates in the uniqueness tuple as ``''``. Duplicate
        tuples and ``extid_`` id collisions surface as ``external_identity`` /
        ``entity_id``; an unknown ``user_id`` surfaces as
        :class:`~app.storage.contract.ReferenceNotFoundError` via the FK.
        """
        conn = self._connection()
        try:
            self._insert_external_identity_row(conn, identity)
        except sqlite3.Error as exc:
            # Covers IntegrityError (translated per constraint) and every
            # other driver failure (lock timeout, disk fault): roll the
            # implicit transaction back so the thread-local connection is
            # never left stale, and raise only domain errors (contract:
            # sqlite3 exceptions must not escape the adapter).
            conn.rollback()
            raise _translate_driver_error(exc) from exc
        conn.commit()
        return identity

    def get_user_by_external_identity(
        self,
        *,
        provider: IdentityProvider,
        provider_subject: ProviderSubject,
        provider_tenant: ProviderTenant | None = None,
    ) -> User:
        """Resolve the identity tuple to the internal :class:`User`.

        Matches only the ``external_identities`` tuple (tenant normalized the
        same way writes store it) and projects the owning ``users`` row — the
        provider subject is never compared against ``users.id``, and no
        identity/row data crosses the boundary. A miss raises
        :class:`~app.storage.contract.EntityNotFoundError`; it is Phase 03's
        "needs provisioning" signal and never a ``None`` return.
        """
        conn = self._connection()
        row = conn.execute(
            "SELECT u.* FROM users u"
            " JOIN external_identities e ON e.user_id = u.id"
            " WHERE e.provider = ? AND e.provider_subject = ? AND e.provider_tenant = ?",
            (
                str(provider),
                provider_subject,
                encode_provider_tenant(provider_tenant),
            ),
        ).fetchone()
        if row is None:
            raise EntityNotFoundError("no external identity matches the given tuple")
        return user_from_row(row)

    # -- Organizations and memberships (task 4) -------------------------------

    def _insert_organization_row(
        self,
        conn: sqlite3.Connection,
        organization: Organization,
    ) -> None:
        """Insert one organization row inside the **caller's** transaction.

        Shared by :meth:`create_organization` and :meth:`provision_user`;
        the helper never commits or rolls back (transaction discipline
        belongs to the calling contract method).
        """
        conn.execute(
            "INSERT INTO organizations"
            " (id, name, slug, type, status, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(organization.id),
                organization.name,
                organization.slug,
                str(organization.type),
                str(organization.status),
                encode_timestamp(organization.created_at),
                encode_timestamp(organization.updated_at),
            ),
        )

    def create_organization(self, organization: Organization) -> Organization:
        """Persist a new organization and echo the caller-supplied entity back.

        Storage mints nothing: the row is exactly ``organization``. Duplicate
        slugs and ``org_`` id collisions surface as translated
        :class:`~app.storage.contract.DuplicateEntityError` kinds
        (``organization_slug`` / ``entity_id``); the failed transaction is
        rolled back so the rejected write leaves no trace.
        """
        conn = self._connection()
        try:
            self._insert_organization_row(conn, organization)
        except sqlite3.Error as exc:
            # Covers IntegrityError (translated per constraint) and every
            # other driver failure (lock timeout, disk fault): roll the
            # implicit transaction back so the thread-local connection is
            # never left stale, and raise only domain errors (contract:
            # sqlite3 exceptions must not escape the adapter).
            conn.rollback()
            raise _translate_driver_error(exc) from exc
        conn.commit()
        return organization

    def get_organization(self, organization_id: OrganizationId) -> Organization:
        """Load an organization by ``org_`` identity; a miss raises
        ``EntityNotFoundError``."""
        conn = self._connection()
        row = conn.execute(
            "SELECT * FROM organizations WHERE id = ?",
            (str(organization_id),),
        ).fetchone()
        if row is None:
            raise EntityNotFoundError(f"no organization with id {organization_id!r}")
        return organization_from_row(row)

    def list_user_organizations(self, user_id: UserId, page: PageParams) -> Page[Organization]:
        """Page through organizations where the user holds an **active**
        membership (contract-pinned domain operation: ``disabled`` is a
        suspension and hides the organization; Phase 04 re-checks roles).

        Ordered by ``(organizations.created_at, organizations.id)`` ascending;
        the ``memberships_pair_unique`` index guarantees at most one
        membership row per ``(organization, user)``, so the join cannot
        duplicate organizations. ``limit`` is re-clamped as defense in depth
        below ``PageParams`` and the cursor is validated against this list's
        scope tag (foreign/tampered tokens raise ``InvalidCursorError``).
        """
        conn = self._connection()
        limit = clamp_limit(page.limit)
        after = (
            decode_cursor(CURSOR_SCOPE_USER_ORGANIZATIONS, page.cursor)
            if page.cursor is not None
            else None
        )
        sql = (
            "SELECT o.* FROM organizations o"
            " JOIN memberships m ON m.organization_id = o.id"
            " WHERE m.user_id = ? AND m.status = ?"
        )
        params: list[object] = [str(user_id), str(MembershipStatus.ACTIVE)]
        if after is not None:
            sql += " AND (o.created_at > ? OR (o.created_at = ? AND o.id > ?))"
            position = encode_timestamp(after[0])
            params.extend([position, position, after[1]])
        sql += " ORDER BY o.created_at ASC, o.id ASC LIMIT ?"
        params.append(limit + 1)
        rows = conn.execute(sql, tuple(params)).fetchall()
        return _build_page(
            [organization_from_row(row) for row in rows],
            scope=CURSOR_SCOPE_USER_ORGANIZATIONS,
            limit=limit,
            position=lambda organization: (organization.created_at, str(organization.id)),
        )

    def _insert_membership_row(self, conn: sqlite3.Connection, membership: Membership) -> None:
        """Insert one membership row inside the **caller's** transaction.

        Shared by :meth:`create_membership` and :meth:`provision_user`;
        the helper never commits or rolls back (transaction discipline
        belongs to the calling contract method).
        """
        conn.execute(
            "INSERT INTO memberships"
            " (id, organization_id, user_id, role, status, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(membership.id),
                str(membership.organization_id),
                str(membership.user_id),
                str(membership.role),
                str(membership.status),
                encode_timestamp(membership.created_at),
            ),
        )

    def create_membership(self, membership: Membership) -> Membership:
        """Grant a user a role in an organization (caller-echo).

        ``(organization_id, user_id)`` is unique: a re-grant surfaces as
        ``DuplicateEntityError(kind="membership")`` and a ``mem_`` id
        collision as ``kind="entity_id"`` (both translated). Unknown parent
        organization or user surfaces as
        :class:`~app.storage.contract.ReferenceNotFoundError` via the foreign
        keys — DynamoDB has no FKs, so the same behavior must be replicated
        there (contract obligation).
        """
        conn = self._connection()
        try:
            self._insert_membership_row(conn, membership)
        except sqlite3.Error as exc:
            # Covers IntegrityError (translated per constraint) and every
            # other driver failure (lock timeout, disk fault): roll the
            # implicit transaction back so the thread-local connection is
            # never left stale, and raise only domain errors (contract:
            # sqlite3 exceptions must not escape the adapter).
            conn.rollback()
            raise _translate_driver_error(exc) from exc
        conn.commit()
        return membership

    def get_membership(self, *, organization_id: OrganizationId, user_id: UserId) -> Membership:
        """Load the membership for one ``(organization, user)`` domain tuple.

        The tuple is the lookup key — the ``mem_`` record id never surfaces
        above storage. Any status resolves (this is the suspension check);
        a miss raises :class:`~app.storage.contract.EntityNotFoundError`.
        """
        conn = self._connection()
        row = conn.execute(
            "SELECT * FROM memberships WHERE organization_id = ? AND user_id = ?",
            (str(organization_id), str(user_id)),
        ).fetchone()
        if row is None:
            raise EntityNotFoundError("no membership for that (organization, user) tuple")
        return membership_from_row(row)

    def list_memberships(
        self,
        organization_id: OrganizationId,
        page: PageParams,
    ) -> Page[Membership]:
        """Page through one organization's memberships (all statuses).

        Strictly organization-scoped: the filter is part of the statement, so
        another organization's memberships can never appear. Ordered by
        ``(created_at, id)`` ascending with the same keyset/cursor discipline
        as :meth:`list_user_organizations`.
        """
        conn = self._connection()
        limit = clamp_limit(page.limit)
        after = (
            decode_cursor(CURSOR_SCOPE_MEMBERSHIPS, page.cursor)
            if page.cursor is not None
            else None
        )
        sql = "SELECT * FROM memberships WHERE organization_id = ?"
        params: list[object] = [str(organization_id)]
        if after is not None:
            sql += " AND (created_at > ? OR (created_at = ? AND id > ?))"
            position = encode_timestamp(after[0])
            params.extend([position, position, after[1]])
        sql += " ORDER BY created_at ASC, id ASC LIMIT ?"
        params.append(limit + 1)
        rows = conn.execute(sql, tuple(params)).fetchall()
        return _build_page(
            [membership_from_row(row) for row in rows],
            scope=CURSOR_SCOPE_MEMBERSHIPS,
            limit=limit,
            position=lambda membership: (membership.created_at, str(membership.id)),
        )

    def delete_membership(self, *, organization_id: OrganizationId, user_id: UserId) -> None:
        """Physically remove one ``(organization, user)`` membership.

        Removal is a physical delete (Phase 01 pinned ``disabled`` as
        suspension, not removal), so the pair is free for a fresh membership
        afterwards. Idempotency is *not* provided: a zero-rowcount delete
        rolls back and raises
        :class:`~app.storage.contract.EntityNotFoundError`; whether HTTP
        answers 204 or 404 is Phase 04's decision.
        """
        conn = self._connection()
        try:
            cursor = conn.execute(
                "DELETE FROM memberships WHERE organization_id = ? AND user_id = ?",
                (str(organization_id), str(user_id)),
            )
        except sqlite3.Error as exc:
            # Same discipline as the write methods above: never leave the
            # implicit transaction open, never leak a driver error.
            conn.rollback()
            raise _translate_driver_error(exc) from exc
        if cursor.rowcount == 0:
            conn.rollback()
            raise EntityNotFoundError("no membership for that (organization, user) tuple")
        conn.commit()

    # -- API keys (task 5) -----------------------------------------------------

    def create_api_key(self, api_key: ApiKey) -> ApiKey:
        """Persist a new API-key credential row (caller-echo).

        Storage mints nothing: the row is exactly ``api_key``. The non-secret
        §8 ``key_id`` credential segment is unique (``api_keys_key_id_unique``
        → ``kind="api_key_id"``); a ``key_`` record-id collision surfaces as
        ``kind="entity_id"``; an unknown organization or creating user
        surfaces as :class:`~app.storage.contract.ReferenceNotFoundError` via
        the foreign keys. ``scopes`` are stored through the JSON codec with
        order and duplicates preserved exactly (normalization is Phase 05
        domain work). No plaintext secret exists on the model and none is
        derived or logged here.
        """
        conn = self._connection()
        try:
            conn.execute(
                "INSERT INTO api_keys"
                " (id, organization_id, created_by_user_id, name, key_id, key_prefix,"
                " secret_hash, environment, scopes, status, created_at, last_used_at,"
                " expires_at, revoked_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(api_key.id),
                    str(api_key.organization_id),
                    str(api_key.created_by_user_id),
                    api_key.name,
                    api_key.key_id,
                    api_key.key_prefix,
                    api_key.secret_hash,
                    str(api_key.environment),
                    encode_json_column(list(api_key.scopes)),
                    str(api_key.status),
                    encode_timestamp(api_key.created_at),
                    None
                    if api_key.last_used_at is None
                    else encode_timestamp(api_key.last_used_at),
                    None if api_key.expires_at is None else encode_timestamp(api_key.expires_at),
                    None if api_key.revoked_at is None else encode_timestamp(api_key.revoked_at),
                ),
            )
        except sqlite3.Error as exc:
            # Covers IntegrityError (translated per constraint) and every
            # other driver failure (lock timeout, disk fault): roll the
            # implicit transaction back so the thread-local connection is
            # never left stale, and raise only domain errors (contract:
            # sqlite3 exceptions must not escape the adapter).
            conn.rollback()
            raise _translate_driver_error(exc) from exc
        conn.commit()
        return api_key

    def get_api_key(self, api_key_id: ApiKeyId) -> ApiKey:
        """Load a key by its ``key_`` application identity; a miss raises
        ``EntityNotFoundError``.

        Tenancy is deliberately **not** filtered here (contract-pinned): the
        §8 verification path must resolve the organization *from* the key, so
        the full row is returned regardless of organization and enforcing the
        §14 org-scoped route contract is the Phase 05 service's check of
        ``api_key.organization_id``, not a storage filter. ``api_key_id`` is
        the ``key_`` identity — not the §8 credential segment (see
        :meth:`get_api_key_by_key_id`).
        """
        conn = self._connection()
        row = conn.execute("SELECT * FROM api_keys WHERE id = ?", (str(api_key_id),)).fetchone()
        if row is None:
            raise EntityNotFoundError(f"no api key with id {api_key_id!r}")
        return api_key_from_row(row)

    def get_api_key_by_key_id(self, key_id: KeyId) -> ApiKey:
        """Load a key by the §8 non-secret ``<key-id>`` credential segment.

        Point lookup on the unique segment inside ``fn_live_<key-id>_<secret>``
        (backed by ``api_keys_key_id_unique``) — a different column and type
        from the ``key_`` identity of :meth:`get_api_key`. Returns stored
        truth: after revocation the row still resolves with
        ``status=revoked`` and ``revoked_at`` set, because status is data and
        rejection is Phase 05 verification work. A miss raises
        :class:`~app.storage.contract.EntityNotFoundError`.
        """
        conn = self._connection()
        row = conn.execute("SELECT * FROM api_keys WHERE key_id = ?", (key_id,)).fetchone()
        if row is None:
            raise EntityNotFoundError("no api key carries that credential segment")
        return api_key_from_row(row)

    def list_api_keys(self, organization_id: OrganizationId, page: PageParams) -> Page[ApiKey]:
        """Page through one organization's API keys (all statuses).

        Strictly organization-scoped: the filter is part of the statement, so
        another organization's keys can never appear (the cross-org read path
        is the unfiltered :meth:`get_api_key`, per the pinned tenancy rule).
        Ordered by ``(created_at, id)`` ascending with the same
        keyset/cursor discipline as :meth:`list_memberships`.
        """
        conn = self._connection()
        limit = clamp_limit(page.limit)
        after = (
            decode_cursor(CURSOR_SCOPE_API_KEYS, page.cursor) if page.cursor is not None else None
        )
        sql = "SELECT * FROM api_keys WHERE organization_id = ?"
        params: list[object] = [str(organization_id)]
        if after is not None:
            sql += " AND (created_at > ? OR (created_at = ? AND id > ?))"
            position = encode_timestamp(after[0])
            params.extend([position, position, after[1]])
        sql += " ORDER BY created_at ASC, id ASC LIMIT ?"
        params.append(limit + 1)
        rows = conn.execute(sql, tuple(params)).fetchall()
        return _build_page(
            [api_key_from_row(row) for row in rows],
            scope=CURSOR_SCOPE_API_KEYS,
            limit=limit,
            position=lambda api_key: (api_key.created_at, str(api_key.id)),
        )

    def revoke_api_key(self, api_key_id: ApiKeyId, *, revoked_at: UtcDatetime) -> ApiKey:
        """Transition a key ``active → revoked`` (first-write-wins CAS).

        The conditional UPDATE is the **first statement** of the transaction
        so it acquires the write lock with a fresh snapshot: it matches only
        rows still ``active``, and a concurrent/duplicate revocation blocks
        (``busy_timeout``), then matches zero rows and returns the stored key
        with the **original** ``revoked_at`` preserved — an idempotent
        success, not an error (AGENTS.md requires revocation duplicate
        behavior to be defined and tested). ``revoked_at`` comes from the
        caller (storage never mints timestamps). Only the CAS is idempotent:
        a zero-rowcount miss on an id with **no row at all** rolls back and
        raises :class:`~app.storage.contract.EntityNotFoundError` — absence
        is absence.
        """
        conn = self._connection()
        try:
            cas = conn.execute(
                "UPDATE api_keys SET status = ?, revoked_at = ? WHERE id = ? AND status = ?",
                (
                    str(ApiKeyStatus.REVOKED),
                    encode_timestamp(revoked_at),
                    str(api_key_id),
                    str(ApiKeyStatus.ACTIVE),
                ),
            )
            if cas.rowcount == 0:
                # Conditional update matched nothing: either the key is
                # already revoked (idempotent success — return stored truth
                # with the *original* revoked_at preserved) or it does not
                # exist at all (absence is absence).
                row = conn.execute(
                    "SELECT * FROM api_keys WHERE id = ?",
                    (str(api_key_id),),
                ).fetchone()
                if row is None:
                    conn.rollback()
                    raise EntityNotFoundError(f"no api key with id {api_key_id!r}")
                conn.commit()
                return api_key_from_row(row)
            # CAS hit: the caller's revoked_at is now the stored truth; read
            # the row back inside this transaction (storage mints nothing
            # else — every other column is exactly what was persisted).
            row = conn.execute(
                "SELECT * FROM api_keys WHERE id = ?",
                (str(api_key_id),),
            ).fetchone()
            conn.commit()
            return api_key_from_row(row)
        except sqlite3.Error as exc:
            # Same discipline as the write methods above: never leave the
            # implicit transaction open, never leak a driver error.
            conn.rollback()
            raise _translate_driver_error(exc) from exc

    # -- Audit (task 6) --------------------------------------------------------

    def _insert_audit_event_row(self, conn: sqlite3.Connection, audit_event: AuditEvent) -> None:
        """Insert one audit row inside the **caller's** transaction.

        Shared by :meth:`append_audit_event` (standalone path, the shape
        Phase 03-05 services use) and :meth:`provision_user` (batch path,
        task 7): the helper never commits or rolls back — transaction
        discipline belongs to the calling contract method. Storage mints
        nothing: the row is exactly the caller-supplied event, with
        ``metadata`` stored through the JSON codec (exact round-trip) and
        ``actor_type`` stored verbatim (the §10 ``user``/``api_key`` strings;
        the model boundary already pins the actor-type/actor-id consistency).
        """
        conn.execute(
            "INSERT INTO audit_events"
            " (id, organization_id, actor_type, actor_id, action, target_type,"
            " target_id, metadata, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(audit_event.id),
                str(audit_event.organization_id),
                audit_event.actor_type,
                str(audit_event.actor_id),
                audit_event.action,
                audit_event.target_type,
                audit_event.target_id,
                encode_json_column(audit_event.metadata),
                encode_timestamp(audit_event.created_at),
            ),
        )

    def append_audit_event(self, audit_event: AuditEvent) -> None:
        """Append one fully formed audit event (standalone write path).

        Returns ``None`` — storage mints nothing and re-reads nothing, so
        there is nothing to return (contract-pinned). Phase 03-05 services
        use this for events outside any compound operation
        (``membership.removed``, ``api_key.revoked``, ...); only provisioning
        batches go through :meth:`provision_user`, which shares the row-insert
        helper above. A duplicate ``aud_`` record id surfaces as
        ``DuplicateEntityError(kind="entity_id")`` and an unknown
        organization as :class:`~app.storage.contract.ReferenceNotFoundError`
        via the foreign key (the actor id is §10 application identity, not an
        FK — enforced at the model boundary). There is no audit read or list
        surface in this phase: append is write-only by contract, and
        ``metadata`` round-trips exactly as JSON.
        """
        conn = self._connection()
        try:
            self._insert_audit_event_row(conn, audit_event)
        except sqlite3.Error as exc:
            # Covers IntegrityError (translated per constraint) and every
            # other driver failure (lock timeout, disk fault): roll the
            # implicit transaction back so the thread-local connection is
            # never left stale, and raise only domain errors (contract:
            # sqlite3 exceptions must not escape the adapter).
            conn.rollback()
            raise _translate_driver_error(exc) from exc
        conn.commit()

    # -- Compound operations (task 7; Phase 04 task 1) --------------------------

    def _resolve_provision_race_user_id(
        self,
        conn: sqlite3.Connection,
        *,
        identity: ExternalIdentity,
        email: str,
    ) -> UserId | None:
        """Best-effort winner resolution after a raced batch rolled back.

        Runs post-rollback (autocommit, so the read sees the concurrent
        winner's committed rows): re-read the identity row for the batch's
        ``(provider, provider_subject, tenant_normalized)`` tuple, falling
        back to a users-by-email read. Both reads are adapter-internal — the
        contract gains no separate resolve method — and return the winner's
        ``usr_`` id so Phase 03 converges without a second query, or ``None``
        when neither resolves.
        """
        row = conn.execute(
            "SELECT user_id FROM external_identities"
            " WHERE provider = ? AND provider_subject = ? AND provider_tenant = ?",
            (
                str(identity.provider),
                identity.provider_subject,
                encode_provider_tenant(identity.provider_tenant),
            ),
        ).fetchone()
        if row is not None:
            return UserId(row["user_id"])
        row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if row is not None:
            return UserId(row["id"])
        return None

    def provision_user(
        self,
        *,
        user: User,
        identity: ExternalIdentity,
        organization: Organization,
        membership: Membership,
        audit_events: Sequence[AuditEvent],
    ) -> ProvisionedUser:
        """Atomically provision user + identity + organization + membership +
        audit events in one transaction (spec §6/§12).

        ``BEGIN IMMEDIATE`` is the first statement so the write lock is held
        *before* any read snapshot exists: a concurrent loser blocks on
        ``busy_timeout``, then observes the winner's committed rows and fails
        on the real UNIQUE constraint — never on a deferred-upgrade
        ``SQLITE_BUSY_SNAPSHOT`` (which the busy handler would not retry).
        All rows go through the shared ``_insert_*_row`` helpers, so the
        stored encoding is identical to the standalone paths; nothing is
        committed until the whole batch has succeeded.

        Duplicate/concurrency semantics (contract-pinned): any UNIQUE
        violation on ``users.email`` **or** the identity tuple is spec §6's
        concurrent-first-login race (both attempts carry the same email and
        identity tuple, distinct record ids) and surfaces as
        :class:`~app.storage.contract.DuplicateExternalIdentityError` with
        ``existing_user_id`` resolved post-rollback by
        :meth:`_resolve_provision_race_user_id`. Other UNIQUE violations
        (organization slug, membership pair, record-id PKs) propagate as
        their own translated :class:`~app.storage.contract.DuplicateEntityError`
        kind, and FK violations (a parent the batch does not itself create)
        as :class:`~app.storage.contract.ReferenceNotFoundError`. Every
        failure path rolls the whole batch back: no partial user, identity,
        organization, membership, or audit rows survive.

        The returned :class:`~app.storage.contract.ProvisionedUser` echoes
        the caller-supplied objects unchanged (caller-echo contract: storage
        mints nothing and does not re-read what it wrote).
        """
        conn = self._connection()
        # Materialize once: the insert loop and the caller-echo tuple below
        # must share one iteration (a one-shot argument would otherwise
        # persist rows but echo an empty batch).
        events = tuple(audit_events)
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._insert_user_row(conn, user)
            self._insert_external_identity_row(conn, identity)
            self._insert_organization_row(conn, organization)
            self._insert_membership_row(conn, membership)
            for audit_event in events:
                self._insert_audit_event_row(conn, audit_event)
        except sqlite3.Error as exc:
            # Roll back first: the race-resolution reads below must run in
            # autocommit so they see the *concurrent winner's* committed
            # rows, not this rolled-back batch.
            conn.rollback()
            translated = _translate_driver_error(exc)
            if isinstance(translated, DuplicateEntityError) and translated.kind in (
                DuplicateEntityKind.USER_EMAIL,
                DuplicateEntityKind.EXTERNAL_IDENTITY,
            ):
                # §6 race mapping (contract-pinned): email/identity-tuple
                # collisions inside a provisioning batch are never reported
                # as a plain email conflict.
                raise DuplicateExternalIdentityError(
                    existing_user_id=self._resolve_provision_race_user_id(
                        conn, identity=identity, email=user.email
                    )
                ) from exc
            raise translated from exc
        conn.commit()
        return ProvisionedUser(
            user=user,
            identity=identity,
            organization=organization,
            membership=membership,
            audit_events=events,
        )

    def provision_organization(
        self,
        *,
        organization: Organization,
        membership: Membership,
        audit_events: Sequence[AuditEvent],
    ) -> ProvisionedOrganization:
        """Atomically write organization + membership + audit events in one
        transaction (Phase 04 breakdown decision 2; contract-pinned).

        ``BEGIN IMMEDIATE`` is the first statement so the write lock is held
        *before* any read snapshot exists (same discipline as
        :meth:`provision_user`): a concurrent loser on the slug UNIQUE blocks
        on ``busy_timeout``, then observes the winner's committed row and
        fails on the real constraint. All rows go through the shared
        ``_insert_*_row`` helpers, so the stored encoding is identical to the
        standalone paths; nothing is committed until the whole batch has
        succeeded, and every failure path is fully rolled back.

        Conflict semantics deliberately differ from :meth:`provision_user`:
        there is **no race-convergence mapping** here. A taken slug is a
        plain translated :class:`~app.storage.contract.DuplicateEntityError`
        (``kind="organization_slug"``), taken record ids are
        ``kind="entity_id"``, and an unknown ``membership.user_id`` — the
        only parent the batch does not itself create — surfaces as
        :class:`~app.storage.contract.ReferenceNotFoundError` via the foreign
        key. The returned :class:`~app.storage.contract.ProvisionedOrganization`
        echoes the caller-supplied objects unchanged (caller-echo contract:
        storage mints nothing and does not re-read what it wrote).
        """
        conn = self._connection()
        # Materialize once: the insert loop and the caller-echo tuple below
        # must share one iteration (a one-shot argument would otherwise
        # persist rows but echo an empty batch).
        events = tuple(audit_events)
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._insert_organization_row(conn, organization)
            self._insert_membership_row(conn, membership)
            for audit_event in events:
                self._insert_audit_event_row(conn, audit_event)
        except sqlite3.Error as exc:
            # Roll back the whole batch: a rejected organization write leaves
            # no partial organization, membership, or audit rows, and the
            # thread-local connection is never left inside an open
            # transaction. No winner-resolution reads: slug conflicts are
            # plain conflicts, never a converge (contract-pinned).
            conn.rollback()
            raise _translate_driver_error(exc) from exc
        conn.commit()
        return ProvisionedOrganization(
            organization=organization,
            membership=membership,
            audit_events=events,
        )


def open_sqlite_storage(path: str | Path) -> Storage:
    """Documented entry point for the SQLite adapter (handoff requirement).

    Returns the adapter typed as the :class:`~app.storage.contract.Storage`
    protocol; application code never constructs ``SQLiteStorage`` directly.
    """
    return SQLiteStorage(path)


__all__ = [
    "CURSOR_SCOPE_API_KEYS",
    "CURSOR_SCOPE_MEMBERSHIPS",
    "CURSOR_SCOPE_USER_ORGANIZATIONS",
    "SCHEMA_VERSION",
    "TABLE_NAMES",
    "UNIQUE_INDEX_NAMES",
    "SQLiteStorage",
    "open_sqlite_storage",
]
