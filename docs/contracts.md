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

Canonical modules:

- Domain: `src/app/models/`
- API schemas and manifest: `src/app/api/schemas/`
- App factory: `src/app/main.py`
- Phase 02 storage boundary: `src/app/storage/`
