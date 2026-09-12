# Current state: storage

Phase 02 is implemented. The storage boundary now exists as a domain contract
(`src/app/storage/contract.py`) plus a SQLite adapter
(`src/app/storage/sqlite.py`), verified by an adapter-neutral conformance suite
(`src/tests/storage_contract/`). No HTTP route or application service reads or
writes through it yet: Phases 03/04/05 are the first consumers of this surface.

## Scope

- `Storage`: a `typing.Protocol` (`@runtime_checkable`) with the 18 pinned
  operations — users and external identities, organizations, memberships, API
  keys, standalone `append_audit_event`, the `provision_user` compound, and
  three paginated lists. Every signature uses only `app.models` types plus the
  `ProvisionedUser` result bundle.
- Domain error vocabulary: `StorageError` base with `EntityNotFoundError`,
  `DuplicateEntityError` (stable `DuplicateEntityKind` discriminator:
  `entity_id`, `external_identity`, `membership`, `organization_slug`,
  `user_email`, `api_key_id`), `DuplicateExternalIdentityError`
  (`existing_user_id`), `ReferenceNotFoundError`, and `InvalidCursorError`.
- SQLite adapter: six tables (`users`, `external_identities`, `organizations`,
  `memberships`, `api_keys`, `audit_events`), schema version 1, and five unique
  indexes (identity tuple, membership pair, organization slug, user email,
  `api_keys.key_id`).
- Conformance suite: 56 adapter-neutral behavior cases in
  `src/tests/storage_contract/suite.py`, run by the SQLite entry
  `test_sqlite_contract.py`.

## Factory and adapter boundary

Application code never constructs an adapter; it uses the documented factory:

```python
from app.storage.sqlite import open_sqlite_storage

storage = open_sqlite_storage("var/feednow-auth.db")  # -> Storage (protocol)
```

- Exact signature: `open_sqlite_storage(path: str | Path) -> Storage`.
- `src/app/storage/__init__.py` re-exports contract symbols only and never
  imports an adapter; adapters are imported by explicit submodule path. A
  subprocess-isolated unit test proves `import app.storage.contract` loads
  neither `sqlite3` nor `app.storage.sqlite`.
- `SQLiteStorage` (returned as `Storage`) uses thread-local connections,
  `journal_mode=WAL`, `busy_timeout` 5 s, and `PRAGMA foreign_keys=ON` applied
  as the first statement on every connection (read-back asserted). Schema init
  is idempotent and stamped with `PRAGMA user_version`; an unknown version
  fails fast. `close()` releases the instance's connections and the instance is
  not reusable afterwards.
- No SQL/SQLite value crosses the boundary: driver errors are translated into
  the domain vocabulary, cursors are opaque, and row→domain reconstruction
  goes through `model_validate`, so corrupt stored values fail loudly instead
  of being coerced.

## Invariants

- **Storage mints nothing.** Every `create_*`/`append_*` receives a fully
  formed domain entity (`usr_`/`org_`/`key_`/`extid_`/`mem_`/`aud_` ids
  and `created_at`/`updated_at` are caller-populated); stored entities read
  back unchanged. `revoke_api_key` takes `revoked_at` from the caller.
- **Missing is an error, never `None`.** Every `get_*` miss and every
  `get_user_by_external_identity` miss raises `EntityNotFoundError` — the
  identity miss is Phase 03's "needs provisioning" signal.
- **Duplicates are domain conflicts.** Uniqueness violations raise
  `DuplicateEntityError` with the matching `kind`; a primary-key collision on
  any table raises `kind="entity_id"`, never a raw driver error.
- **Tenant normalization.** `provider_tenant=None` is stored as the normalized
  empty string `''` and reads back as `None`; the mapping is lossless because
  `ProviderTenant` pins `min_length=1`. Without it, SQLite `UNIQUE` would treat
  NULLs as distinct and let duplicate identities through.
- **Stored timestamps are fixed-width UTC** (`YYYY-MM-DDTHH:MM:SS.ffffffZ`), so
  lexicographic order equals chronological order — the property keyset
  pagination depends on. `to_utc_rfc3339` (API JSON) omits zero microseconds and
  is deliberately not reused for stored columns.
- **Referential integrity.** Child rows with unknown parents
  (identity→user; membership→organization+user; api_key→organization+creator;
  audit→organization) raise `ReferenceNotFoundError`.
- **Key-read tenancy.** `get_api_key`/`revoke_api_key` take only the `key_`
  application identity and return the full row regardless of organization,
  because the §8 verification path resolves the organization *from* the key;
  enforcing org-scoped routes is Phase 05 service work. `get_api_key_by_key_id`
  is the separate point lookup on the non-secret credential segment.
- **Membership lookups are keyed by the `(organization_id, user_id)` tuple**;
  the `mem_` record id never surfaces above storage. `delete_membership` is a
  physical delete and is not idempotent — a second delete raises.
  `list_user_organizations` returns only organizations where the user holds an
  **active** membership (`disabled` is a suspension).

## Transaction and CAS behavior

- `provision_user(*, user, identity, organization, membership, audit_events)`
  writes all rows in one transaction (`BEGIN IMMEDIATE`). `audit_events` is
  required keyword-only: provisioning events are part of the atomic unit.
- Concurrent-first-login race semantics: any uniqueness violation on the user
  email **or** the identity tuple is interpreted as that race and raises
  `DuplicateExternalIdentityError` after a full rollback, with `existing_user_id`
  resolved by the adapter when possible (else `None`) so Phase 03 converges
  without a second query. Other conflicts keep their own
  `DuplicateEntityError.kind`. No failure path leaves partial rows, and two
  identical concurrent provisions produce exactly one success.
- `revoke_api_key` is a first-write-wins compare-and-set on `active → revoked`:
  duplicate and concurrent revocations return the stored key with the
  **original** `revoked_at` preserved (idempotent success); an unknown `key_`
  identity raises `EntityNotFoundError`. A revoked key still resolves through
  `get_api_key_by_key_id` with `status=revoked` — status is data, rejection is
  Phase 05 verification.
- `append_audit_event` is a standalone single-row write returning `None`;
  Phase 03–05 services use it for events outside any compound operation.

## Pagination behavior

- All three lists order by `(created_at, id)` ascending, with `id` as the
  unique tiebreaker that makes traversal deterministic.
- Cursors are opaque base64url payloads carrying the position plus a
  **list-scope tag**, created and decoded only inside `sqlite.py`. A malformed,
  tampered, or foreign cursor (one list's cursor fed to another) raises
  `InvalidCursorError`.
- Adapters fetch `limit + 1` rows to decide `next_cursor` (last page: `None`)
  and re-clamp `limit` via `clamp_limit` as defense in depth below `PageParams`;
  `Page.limit` echoes the effective clamped size. Inserting rows between page
  fetches neither duplicates nor skips unvisited items.

## Conformance invocation and Phase 06 reuse

```bash
uv run pytest src/tests/storage_contract        # suite + SQLite entry
uv run pytest                                   # unit + integration + conformance
```

`suite.py` is imported *unchanged* by each adapter entry point, so it is a
reuse contract:

- **Fixture contract** (from the suite docstring): every entry provides a
  pytest fixture named `storage` that yields an initialized adapter with all
  tables empty, per test. The SQLite entry uses a fresh temporary file through
  `open_sqlite_storage`; the Phase 06 DynamoDB Local entry must provide
  equivalent isolation.
- **Import isolation:** the suite imports only `app.storage.contract` and
  `app.models` (plus pytest/stdlib), asserted by AST and fresh-interpreter
  checks in `test_sqlite_contract.py`; coupling to a concrete adapter happens
  only through the `storage` fixture.
- **Deterministic builders:** `make_user`, `make_organization`, and friends
  live in `suite.py` and use literal prefix-valid IDs and fixed literal
  timestamps — no generators and no `utc_now()`. A Phase 06 entry must not
  reach for generators to satisfy them.

## Verification

- `uv run pytest` — 569 passed (500 unit, 60 storage-contract, 9 integration).
- `uv run pytest src/tests/storage_contract` — 60 passed against a clean
  temporary SQLite database per test.
- `uv run ruff check .`, `uv run ruff format --check .`, `git diff --check` —
  clean.

## Known limitations

- No memory fake: `src/app/storage/memory.py` is deferred until a phase has a
  unit-test need for one (likely 03/04).
- Deferred contract methods, proposed at their owning phase rather than
  smuggled in: `record_api_key_use` (Phase 05), `update_user` /
  `update_organization` (Phases 03/04).
- Audit events are append-only here: no read or list surface (Phase 08).
- HTTP mapping of storage errors (404/409) is not implemented; `app/api` is
  untouched by this phase.
- DynamoDB is not implemented; the contract docstrings carry the obligations
  Phase 06 must replicate (referential integrity inside conditional writes,
  tenant normalization, keyset ordering).
