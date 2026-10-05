# Authorization

Organization tenancy and the membership role policy. A request is first
identified (see [authentication.md](authentication.md)); this doc governs what
that principal may do inside an `org_`, and how a denial is rendered and
audited. The frozen error and status envelope lives in
[contracts.md](contracts.md); cross-adapter and operator concerns are in
[storage.md](storage.md) and [operations.md](operations.md).

## Organization tenancy

The organization surface (`GET/POST/PATCH /v1/organizations`,
`/v1/organizations/{organization_id}/members`) is mounted from the frozen `/v1`
manifest by `build_organizations_router` / `build_members_router`
(`src/app/api/organizations.py`, `src/app/api/members.py`). Handlers carry **no**
authorization logic: each route depends on the shared role-check dependency
(`src/app/auth/organization_access.py`), which composes the published
authentication chain with the pure classifier `classify_access`
(`src/app/services/authorization.py`) and the denial audit.

One request flows: bearer → `build_current_user` (or the
`build_current_principal` prefix dispatcher once a `pepper_source` is wired) →
`get_organization` → `classify_access` → either a frozen
`OrganizationAccess(identity, organization, membership)` is yielded, or a
uniform denial is audited first, then returned.

- **Atomic creation.** `create_organization`
  (`src/app/services/organization.py`) emits exactly one
  `provision_organization` batch — organization + owner membership + creation
  audits. Ownership transfer is also a dedicated atomic unit.
  Unlike first-login provisioning it has **no** race convergence: a taken slug
  is a plain `DuplicateEntityError(kind=organization_slug)`, taken record ids are
  `entity_id`, an unknown membership user is `ReferenceNotFoundError`, and every
  rejected batch is fully rolled back. See [contracts.md](contracts.md).
- **Role policy.** `ROLE_RANK` fixes `viewer < member < org_admin < owner`. Reads
  (any org-scoped GET) require an **active** membership at rank ≥ `viewer`;
  mutations (member add/remove, ownership transfer, org rename) require rank ≥
  `org_admin`. Creation
  requires only authentication — the creator becomes `owner` through the batch.
  `org_admin` can be assigned or removed like other non-owner memberships.
  Ownership transfer is atomic: the selected active member becomes `owner`,
  the former owner becomes `org_admin`, and the action is audited.
- **Precedence.** `classify_access` checks in fixed order — organization status,
  then membership presence, then membership status, then role rank — so the
  denial `reason` is deterministic when several conditions hold, even though the
  HTTP response stays uniform.
- **Uniform, audited 403.** Unknown organization, inactive organization, missing
  membership, inactive membership, and insufficient role all answer the **same**
  byte-identical `403 forbidden`, so no existence oracle leaks. `authorization.denied`
  is appended **whenever the organization row exists**, with metadata exactly
  `{"reason", "operation"}`, **before** the 403. An unknown-organization denial
  cannot be audited (the audit→organization FK has no target — a documented
  exception); an audit-append failure propagates as a **500** (fail-closed),
  never a silent 403.
- **Authentication precedes authorization.** A request that will be denied still
  auto-provisions a first-seen Cognito identity, consistent with `GET /v1/me`.

The org-side denial reasons are `no_membership`, `inactive_membership`,
`inactive_organization`, and `insufficient_role`; all are members of the one
`AccessOutcome` vocabulary.

## Registered-service permissions

The browser handoff and service-code exchange use a FeedNow-owned permission
mapping, separate from API-key scopes and the global application-admin role:

| Active organization role | Available service permissions |
| --- | --- |
| `owner`, `org_admin` | `projects:read`, `projects:write`, `inspect` |
| `member` | `projects:read`, `inspect` |
| `viewer` | `projects:read` |

The issued context is the sorted intersection of this role mapping and the
registered service's allowed permissions. Handoff requires an active user,
organization, and membership. Exchange consumes the code first, then re-reads
those records and confirms that the membership permission snapshot still
matches. A disabled or removed grant cannot exchange successfully. The global
`ApplicationRole.ADMIN` does not add service permissions, and commercial
policy does not appear in this vocabulary.

An organization `org_admin` can transfer ownership with
`POST /v1/organizations/{organization_id}/owner`, naming an active member.
The transfer commits both role changes and an audit event together: the target
becomes `owner` and the former owner becomes `org_admin`.

## Organization names and slugs

First-login provisioning creates a placeholder organization. An authorized
administrator can check a proposed name with
`GET /v1/organizations/{organization_id}/slug-availability?name=...`. The
backend normalizes the name to a lowercase ASCII hyphenated slug and reports
whether that slug is available, excluding the current organization. Renaming
persists the confirmed name and derived slug together. Storage enforces slug
uniqueness on the write itself (including concurrent renames); a collision
returns `409` with a safe organization-name conflict message. SQLite relies on
its unique slug index, while DynamoDB atomically replaces the slug constraint
alongside the organization update.

## Two separate, non-inheriting vocabularies

Organization-membership roles (this doc — `MembershipRole`, `ROLE_RANK`) and the
global `ApplicationRole` are **separate and never inherit** into each other.
Organization `org_admin` is distinct from FeedNow-wide `admin`.
`ApplicationRole` is a closed two-value vocabulary (`user` / `admin`), granted
out of band by the operator, and is enforced by a distinct global-administrator
seam (`build_application_admin_dependency`, `src/app/auth/application_access.py`).
That seam, plus the role-transition operation and its audits, lives in
[administration.md](administration.md). An API key is structurally roleless, so
no key can escalate through either vocabulary.

## Models and modules

- `src/app/models/membership.py` — one `User`'s role-bearing membership in an
  organization (id, organization, user, role, status).
- `src/app/models/organization.py` — the `org_` tenancy row.
- `src/app/models/authorization_context.py` — `AuthorizationContext`,
  resolving the active organization/role for a request.
- `src/app/services/authorization.py` — the pure `ROLE_RANK` / `classify_access`
  rule, the `AccessOutcome` / `AccessDecision` result, the domain errors the
  routers translate, the policy guards, and the audit builders
  (`build_organization_created_audit`, `build_membership_created_audit`,
  `build_membership_removed_audit`, `build_denial_audit`, `audit_denial`) —
  with no FastAPI imports.
- `src/app/auth/organization_access.py` — `OrganizationAccess` and the
  `build_organization_member_dependency` / `build_organization_admin_dependency`
  factories (the single shared seam, including the `pepper_source`-wired
  `human_only` branch).

## Cross-cutting concerns

- **Credentials / scoped access.** The key-carrying scope dependency
  (`build_organization_scope_dependency`) reuses this seam: its human branch
  applies the membership-rank rules above; its API-key branch is org status →
  `organization_mismatch` → `insufficient_scope` (exact-string scope
  membership, no wildcards). Those two denial reasons, plus `human_only`, are
  the credential-side vocabulary; full scope/credential rules are in
  [credentials.md](credentials.md).
- **Global administration.** The unmounted `ApplicationRole.ADMIN` gate and its
  transition operation are in [administration.md](administration.md); operator
  IAM (CDK Lambda/role, deployment) is distinct from this role policy and lives
  in [operations.md](operations.md).
- **Envelopes and parity.** The uniform 403 body, status mapping, and the
  `provision_organization` atomics (one transaction / one `TransactWriteItems`)
  are cross-cutting in [contracts.md](contracts.md) and
  [storage.md](storage.md).
- **Identity and administrator lookup.** Email lookup and application-role
  storage support are described with identity and operator behavior in
  [authentication.md](authentication.md), [administration.md](administration.md),
  and [storage.md](storage.md).
