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
- Storage is reached only through the 19-method `Storage` protocol and the
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
- Organization creation is exactly one `provision_organization` batch
  (organization + owner membership + creation audits) — the only atomic
  unit, because the owner invariant has no repair path. Unlike
  `provision_user` there is no race convergence: a taken slug is a plain
  `DuplicateEntityError(kind=organization_slug)`, taken record ids are
  `entity_id`, and an unknown membership user is `ReferenceNotFoundError`;
  every rejected batch is fully rolled back. Phase 06 must replicate the
  atomics (contract docstring carries the duty).

Authentication boundary (Phase 03):

- Access tokens only: `RS256` exact header match (checked before any claim
  extraction or network fetch), issuer by exact set membership against the
  configured allowlist (never prefix matching, never the library's `issuer=`
  option), `client_id` set membership, `token_use == "access"`, required
  non-empty `email`, 60-second leeway on `exp`/`iat`/`nbf`. Rejections carry
  fixed safe reasons and never mutate storage.
- `JwksSource.signing_key(issuer, kid)` is **issuer-bound**: a `kid` is
  resolved only from that issuer's key set; cross-issuer scanning is
  impossible through the interface.
- A Cognito `sub` becomes `(provider=cognito, provider_subject=sub,
  provider_tenant=None)` — provider fields stop at the service seam; only
  `usr_`/`org_` ids flow onward.
- First-login provisioning is exactly one `provision_user` batch (user,
  identity, personal org, owner membership, three creation audits) sharing
  one clock read and one ID set. Race convergence happens **only** via the
  identity-tuple re-read after `DuplicateExternalIdentityError`;
  `existing_user_id` is an adapter email-fallback value — advisory
  cross-check, never the convergence signal. A re-read miss is a genuine
  email collision: `ProvisioningConflictError`, no partial rows.
- Human `AuthorizationContext`: organization = earliest active membership
  (or the explicit `organization_id`, which requires an active membership in
  an active organization), `roles=[role]`, `scopes=[]`,
  `actor_type="user"`, `actor_id=usr_`.
- Status mapping: `TokenValidationError`→401, `DisabledUserError` /
  `NoActiveOrganizationError`→403, `ProvisioningConflictError`→409,
  `TokenProviderUnavailableError`→503 — all through the frozen `Error`
  envelope; 503 carries `internal_error` (no new code invented).
- `GET /v1/me` returns the caller's `User` fields only — the internal `usr_`
  id is the only identifier returned; no `sub`, no `client_id`, no token
  material, no record ids (`extid_`/`mem_`/`aud_`).

Authorization boundary (Phase 04):

- Role rank is `viewer < member < admin < owner` (`ROLE_RANK`). Org-scoped
  reads require an active membership (any role); member add/remove require
  rank ≥ admin. Organization creation requires only authentication and the
  creator becomes `owner` through the atomic batch. `owner` is not
  grantable, not removable, and not changeable through the API (policy plus
  the deliberate absence of storage update methods).
- Unknown org, inactive org, missing membership, inactive membership, and
  insufficient role all answer the same 403 with one fixed message
  (existence-oracle-free). `authorization.denied` is audited whenever the
  organization row exists with metadata exactly `{reason, operation}`;
  unknown-org denials are structurally unaudited (FK exception); an
  audit-append failure on a denial is a 500, never a silent 403
  (fail-closed).
- Mutation audits: `organization.created` `{"type"}` + `membership.created`
  `{"role": "owner"}` inside the creation batch; `membership.created` /
  `membership.removed` (role at removal) appended standalone **after** the
  successful write. No `mem_` record id or email appears in any response
  body; record ids live only in audit targets.
- Status mapping (frozen codes only): type/owner-role guards and foreign
  cursors → 400 `validation_error`; non-member and unknown target `usr_` →
  404 `not_found`; slug conflict, duplicate pair, and owner immutability →
  409 `conflict`; any other `StorageError` stays untranslated to the 500
  handler.
- The shared dependency factories `build_organization_member_dependency` /
  `build_organization_admin_dependency` (keyed on the resolved context's
  actor, so Phase 05's `api_key` branch joins at the same seam) yield a
  frozen `OrganizationAccess(identity, organization, membership)`; shipped
  routers carry no authz logic and register manifest entries only.

Canonical modules:

- Domain: `src/app/models/`
- API schemas and manifest: `src/app/api/schemas/`
- App factory: `src/app/main.py`
- Storage contract (protocol, errors, `ProvisionedUser`,
  `ProvisionedOrganization`): `src/app/storage/contract.py`
- SQLite adapter and factory: `src/app/storage/sqlite.py`
- Adapter-neutral storage conformance suite:
  `src/tests/storage_contract/`
- Token contract and verifier: `src/app/auth/cognito.py` (+ `errors.py`,
  `jwks.py`, `dependencies.py`)
- Resolution/provisioning rules and ID minting:
  `src/app/services/identity.py`, `src/app/services/idgen.py`
- Authorization rules and audit builders: `src/app/services/authorization.py`
- Shared organization-access dependency: `src/app/auth/organization_access.py`
- Tenancy services and routers: `src/app/services/{organization,member}.py`,
  `src/app/api/{organizations,members}.py`
- First mounted router: `src/app/api/me.py`
