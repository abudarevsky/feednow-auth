# Contracts

This document describes the currently implemented contract. Future changes
belong in the transformation plan that owns them; update this document only
when that behavior is actually implemented and verified.

- Application IDs are `usr_`, `org_`, and `key_`; provider subjects remain
  constrained strings and are never coerced into application IDs.
- Record IDs `extid_`, `mem_`, and `aud_` are internal and never appear in
  paths or API response payloads.
- Naive datetimes are rejected; JSON timestamps use UTC ISO-8601 with `Z`.
- `Page[T]` uses an opaque cursor; only storage adapters create or decode it.
- API schemas forbid unknown fields and never expose hashes or credentials,
  except the one-time `ApiKeyCreatedResponse.key`.
- Every `/v1` route must appear in `ENDPOINTS`; deletes are 204 with no body.
- Product APIs must not require a synchronous auth-service call for every
  protected request.
- Storage is reached only through the 18-method `Storage` protocol and the
  documented factory `open_sqlite_storage(path: str | Path) -> Storage`.
  Signatures carry domain types exclusively: no row, driver exception,
  session, or interpretable cursor may cross the boundary.
- Storage never mints IDs or timestamps; writes take fully formed domain
  entities and read back unchanged.
- Every storage failure is a `StorageError` subclass. Missing entities raise
  `EntityNotFoundError` (never `None`); uniqueness violations raise
  `DuplicateEntityError` with a stable `kind` (`entity_id`,
  `external_identity`, `membership`, `organization_slug`, `user_email`,
  `api_key_id`); unknown parents raise `ReferenceNotFoundError`; bad cursors
  raise `InvalidCursorError`.
- Lists are ordered by `(created_at, id)` ascending with `id` as the
  deterministic keyset tiebreaker; out-of-range limits are clamped, not
  rejected.

Canonical modules:

- Domain: `src/app/models/`
- API schemas and manifest: `src/app/api/schemas/`
- App factory: `src/app/main.py`
- Storage contract (protocol, errors, `ProvisionedUser`):
  `src/app/storage/contract.py`
- SQLite adapter and factory: `src/app/storage/sqlite.py`
- Adapter-neutral storage conformance suite: `src/tests/storage_contract/`
