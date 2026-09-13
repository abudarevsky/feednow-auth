# Current state: organizations, memberships, and authorization

Phase 04 is implemented. Authenticated users manage organizations and
memberships through six mounted §14 routes, every organization-scoped
request passes one shared access dependency, and denials are uniform,
existence-oracle-free, and audited wherever the audit→organization FK has a
target. Organization creation is a single atomic batch (organization +
owner membership + two audits). No API keys (Phase 05), no DynamoDB
(Phase 06), no deployment changes (Phase 07).

## Scope

- `src/app/storage/contract.py` / `src/app/storage/sqlite.py`: the 19th
  protocol method — `provision_organization(*, organization, membership,
  audit_events) -> ProvisionedOrganization` — one `BEGIN IMMEDIATE`
  transaction over the shared row-insert helpers. Deliberately **no**
  race-convergence semantics (unlike `provision_user`): a taken slug is a
  plain `DuplicateEntityError(kind="organization_slug")`, taken record ids
  are `entity_id`, an unknown `membership.user_id` is
  `ReferenceNotFoundError`, and every rejected batch is fully rolled back.
  The contract docstring carries the Phase 06 replication obligation.
- `src/app/services/authorization.py`: the pure role policy and denial
  rules — `ROLE_RANK` (`viewer < member < admin < owner`),
  `classify_access` (fixed precedence), `AccessOutcome`/`AccessDecision`,
  the four decision-4 denial reasons as the only `reason` vocabulary, the
  audit builders (`build_organization_created_audit`,
  `build_membership_created_audit`, `build_membership_removed_audit`,
  `build_denial_audit`), `audit_denial`, the guards
  `require_selectable_organization_type` (customer only) and
  `require_assignable_member_role` (not owner), and the service domain
  errors the routers translate (decision 6 table below). No FastAPI
  imports in this module.
- `src/app/auth/organization_access.py`: `OrganizationAccess` (frozen:
  `identity`, `organization`, `membership`) and the two dependency
  factories `build_organization_member_dependency` /
  `build_organization_admin_dependency` composing the published
  `build_current_user` chain with `classify_access` and the denial audit.
- `src/app/services/organization.py`: `create_organization` (type guard →
  batch build → one `provision_organization` call → slug-conflict
  translation) and `list_organizations` pass-through; injectable
  `now`/`ids`, one clock read and one ID set per creation.
- `src/app/services/member.py`: `add_member` (owner-role guard →
  `create_membership` → error translation → `membership.created` audit
  **after** the write), `remove_member` (`get_membership` first → owner
  immutability guard → `delete_membership` → `membership.removed` audit
  after commit), `list_members` pass-through.
- `src/app/api/organizations.py` / `src/app/api/members.py`: routers
  registering the six frozen manifest entries from the spec data itself
  (`build_organizations_router(storage, verifier)`,
  `build_members_router(storage, verifier)`); no authz logic in handlers.

## Mounted HTTP surface

| Route | Access rule | Success | Failure additions |
| --- | --- | --- | --- |
| `GET /v1/organizations` | authenticated (list is caller-scoped by contract) | 200 `Page[OrganizationResponse]` | 400 `validation_error` (bad cursor) |
| `POST /v1/organizations` | authenticated; creator becomes `owner` | 201 `OrganizationResponse` | 400 (type not `customer`), 409 (slug taken) |
| `GET /v1/organizations/{organization_id}` | member dependency (any active role) | 200 `OrganizationResponse` | 403 uniform denial |
| `GET /v1/organizations/{organization_id}/members` | member dependency | 200 `Page[MemberResponse]` (all statuses) | 400 (bad cursor), 403 |
| `POST /v1/organizations/{organization_id}/members` | admin dependency (rank ≥ admin) | 201 `MemberResponse` | 400 (`role=owner`), 404 (unknown target `usr_`), 409 (pair exists), 403 |
| `DELETE /v1/organizations/{organization_id}/members/{user_id}` | admin dependency | 204 empty body | 404 (not a member), 409 (target is owner), 403 |

## Role policy (decision 3)

- Reads require an **active** membership at rank ≥ `viewer` (any role);
  mutations (member add/remove) require rank ≥ `admin`. Organization
  creation requires only authentication — the creator owns what they create.
- The `owner` role is **not grantable** through the membership API, **not
  removable** (nobody, including owners, can delete an owner membership),
  and **not changeable** — enforced by policy plus the deliberate absence
  of any update method in the storage contract.
- Consequences: leaving an organization you own is impossible;
  `member`/`viewer` cannot self-remove either (removal requires rank ≥
  admin), while an admin may remove themselves or a peer admin (no
  admin-vs-admin special case); every organization keeps exactly its
  creator/provisioner as owner.

## Denial semantics (decision 4)

Unknown organization, inactive organization, missing membership, inactive
membership, and insufficient role all answer **403 `forbidden` with one
fixed message** ("you do not have permission to access this organization")
— byte-identical bodies, mirroring Phase 03 decision 9 so the two seams
never disagree and no existence oracle leaks.

- `classify_access` checks in fixed precedence — organization status, then
  membership presence, then membership status, then role rank — so when
  several conditions hold the audit `reason` is deterministic even though
  HTTP stays uniform.
- `authorization.denied` is appended **whenever the organization row
  exists**, with metadata exactly `{"reason": <denial reason>, "operation":
  <manifest operation_id>}` — no email, no `sub`, no token, no caller role
  beyond what the reason implies.
- Unknown-organization denials cannot be audited (the §4
  `AuditEvent.organization_id` FK has no target) — the documented exception
  to "denials create authorization.denied", escalated for a §16 revision.
- Audit-append failure propagates: a denial that cannot be audited is a
  **500**, never a silent 403 (fail-closed).
- Authentication failures (401) precede the dependency and are not
  denials; a request that will be denied still auto-provisions a first-seen
  Cognito identity (authn precedes authz, spec §6).
- The path `{organization_id}` is the tenant selector; the
  `AuthorizationContext.organization_id` (earliest-active default) does
  **not** have to match — otherwise a user could only manage their earliest
  organization.

## Error mapping (decision 6; frozen envelope codes only)

| Service/storage condition | Status | `code` |
| --- | --- | --- |
| `OrganizationTypeNotSelectableError`, `OwnerRoleNotAssignableError`, `InvalidCursorError` | 400 | `validation_error` |
| `MemberNotFoundError`, `TargetUserNotFoundError` (translated from `ReferenceNotFoundError`) | 404 | `not_found` |
| `OrganizationSlugConflictError`, `MembershipConflictError` (from `kind=membership`), `OwnerMembershipImmutableError` | 409 | `conflict` |
| any other `StorageError` | — | untranslated → frozen 500 `internal_error` (adapter text never echoed) |

## Audit vocabulary after Phase 04 (§16)

| Action | Metadata (exact) | Target | When |
| --- | --- | --- | --- |
| `organization.created` | `{"type": <org type>}` | `organization`/new `org_` | inside the `provision_organization` batch (also provisioning) |
| `membership.created` | `{"role": <granted role>}` | `membership`/new `mem_` | batch (owner) or standalone **after** a successful API add |
| `membership.removed` | `{"role": <role at removal>}` | `membership`/removed `mem_` id | **after** the delete commits |
| `authorization.denied` | `{"reason", "operation"}` | none (broad action) | every denial with an existing org row, before the 403 |

Ordering rationale: a mutation that failed must never audit as success; a
committed mutation whose audit append fails returns 500 with the mutation
persisted (accepted, documented limitation — SQLite has no cross-call
transaction; the compound batch is the only atomic unit).

## Concurrency behavior (proven by barrier races, 20 repeats each)

- 8 concurrent `POST /v1/organizations` with one slug → exactly one 201
  (one org + one owner membership + two audits); losers 409 — a slug
  conflict is never a converge.
- 8 concurrent adds of one target user → one membership, losers 409.
- 2 concurrent removals of one pair → exactly one 204 and one 404 (the
  contract pins `delete_membership` non-idempotent; the service translates
  the loser's miss to `MemberNotFoundError`); one `membership.removed`.

## Published interfaces (what Phases 05/06/08 code against)

| Interface | Module | Consumers |
| --- | --- | --- |
| `build_organization_member_dependency(storage, verifier, operation_id)` / `build_organization_admin_dependency(...)` → `OrganizationAccess` | `src/app/auth/organization_access.py` | Phase 05 api-key-scoped routes (same seam, `api_key` actor branch); Phase 07 wiring |
| `classify_access(organization, membership, min_role)` / `ROLE_RANK` / `AccessOutcome` | `src/app/services/authorization.py` | any future role policy surface (the reusable rule is the enum + precedence, not the HTTP) |
| `Storage.provision_organization(...)` + `ProvisionedOrganization` | `src/app/storage/contract.py` | Phase 06 (must replicate atomically; conformance suite cases are adapter-neutral) |
| `build_organizations_router(storage, verifier)` / `build_members_router(storage, verifier)` | `src/app/api/organizations.py`, `src/app/api/members.py` | deployment entrypoint (`create_app(routers=[...])`) |
| `audit_denial(...)` + the four `build_*_audit` helpers | `src/app/services/authorization.py` | Phase 05 denial/mutation audits (same metadata discipline) |

Example (production wiring shape; Phase 07 mounts all three routers on the
same storage/verifier instances):

```python
from app.api.members import build_members_router
from app.api.me import build_me_router
from app.api.organizations import build_organizations_router
from app.auth.cognito import CognitoAccessTokenVerifier
from app.auth.jwks import CognitoJwksSource
from app.main import create_app
from app.storage.sqlite import open_sqlite_storage

issuers = ["https://cognito.us-east-1.amazonaws.com/POOL_ID"]  # from config
verifier = CognitoAccessTokenVerifier(
    CognitoJwksSource(issuers), allowed_issuers=issuers, allowed_client_ids=[APP_CLIENT_ID]
)
storage = open_sqlite_storage("var/feednow-auth.db")
app = create_app(
    routers=[
        build_me_router(storage, verifier),
        build_organizations_router(storage, verifier),
        build_members_router(storage, verifier),
    ]
)
```

## Verification

- `uv run pytest` — **943 passed** (204 of them Phase 04): 19 storage
  compound cases (4 adapter-neutral suite cases — atomic write with full
  read-back, slug conflict as plain duplicate, taken `org_`/`mem_`/`aud_`
  ids as `entity_id`, unknown membership user — plus contract-surface and
  SQLite-internal proofs), 69 authorization-rule unit tests (full
  decision-4 classification matrix with precedence cells, denial audit
  shape, builders deterministic under injected `now`/ids, guards), 7
  access-dependency tests on a probe router (five byte-identical 403s,
  audit-present/absent proofs, fail-closed 500), 23 organization endpoint
  integration tests (owner/admin/member/viewer × outsider matrix on all
  three org routes, batch row proofs, cursor clamping), 24 member endpoint
  integration tests (role matrix on all three member routes, owner
  immutability, cross-tenant zero-mutation), 62 acceptance proofs (3 × 20
  barrier races with direct-count assertions + the audit-hygiene sweep).
- `uv run pytest src/tests/storage_contract` — 64 passed (60 suite cases +
  4 harness isolation proofs); the four new `provision_organization` cases
  are adapter-neutral and Phase 06 re-runs them against DynamoDB Local.
- Tests use signed fixtures and the loopback `JwksTestServer`
  (`src/tests/support/cognito.py`) — never a live Cognito pool; role-matrix
  users are seeded, not provisioned; audit assertions read the SQLite file
  directly (no audit read surface in the contract).
- `uv run ruff check .` and `uv run ruff format --check .` clean;
  `git diff --check` clean; the subprocess-isolated no-`boto3` import
  proof for `app.main` stays green (Phase 04 adds no runtime dependencies).

## Known limitations

- **No organization rename/disable and no membership role change or
  re-enable**: the storage contract has no update methods and adding them
  has no spec basis this phase (deferred, explicit).
- `MembershipStatus.DISABLED` is dead state: nothing in Phase 04 sets it
  and nothing clears it; adding to a disabled pair is a 409 (pair
  uniqueness) with no re-enable path.
- `member`/`viewer` cannot self-remove (removal requires rank ≥ admin);
  owners cannot leave their own organization (owner immutability).
- Add-member distinguishes unknown-target 404 from duplicate-pair 409, so
  an organization admin can probe whether a `usr_` exists globally —
  accepted because IDs are uuid4-based and unguessable.
- Audit-append-after-commit window: a crash between a committed mutation
  and its audit loses the audit row, not the mutation (single-statement
  writes have no shared transaction with the append).
- Unknown-organization 403s are structurally unaudited (FK exception,
  decision 4).
- `internal` organizations are not creatable or manageable through the API
  (operator-managed; no spec surface yet).
- The list endpoints return all membership statuses by contract
  (`MemberResponse.status` carries it); no filter is invented.
