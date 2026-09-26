# Local account milestone — current behavior

The local account milestone adds organization-name confirmation, application
administration reads, and service-bound API keys. It is composed only in the
local Docker runtime; the production Lambda runtime does not mount the admin
routes or local acceptance probe.

## Organization names

New personal workspaces carry `name_status=placeholder`. Owners can rename an
organization with `PATCH /v1/organizations/{organization_id}`. The handler
trims the name, sets `name_status=confirmed`, and keeps `created_at` unchanged.
SQLite schema v4 adds `name_status`; migration backfills existing personal
workspaces as placeholders and existing non-personal organizations as
confirmed. Schema v5 adds nullable `suspended_at`, which remains null until an
organization is suspended. The account page presents the name status and a
rename form.

## Local administration and organization lifecycle

The Docker runtime mounts the application-admin-gated routes listed in
`src/app/api/schemas/manifest.py`: global organization and active-membership
counts, paginated case-insensitive organization search, organization details,
and paginated membership facts. These routes are mounted only in the local
Docker runtime and the `LocalAdminStorage` extension, implemented by the local
SQLite adapter. Admin authorization uses the verified backend user and global
application role, including when that user has no active organization.
Suspension records the first suspended_at timestamp and revokes every
organization API key while leaving member accounts and memberships active, so
users can sign in and see their suspended status. Backend organization
authorization blocks business operations. Application administrators can
reactivate an organization, clearing suspended_at and restoring organization
access; keys revoked during suspension remain revoked. Global application
administrators remain active to administer suspended tenants. Suspended organizations show a status badge
in organization lists and at the top of loaded details. Deletion requires
exact organization-name confirmation;
one storage transaction first applies those suspension transitions, then
removes the organization and every associated user account, membership, key,
audit event, session, and external identity. This follows the current product
rule that each user belongs to one organization. The browser menu and
route read the backend's
`application_role`; non-admins receive the same unavailable state without
issuing admin requests.

Authenticated local browser sessions bootstrap `GET /v1/csrf` before the UI
exposes account routes. The route sets a readable `feednow_csrf` cookie whose
value is an HMAC bound to the opaque session ID. Unsafe `/v1` requests carrying
that session cookie must submit the same value in `X-CSRF-Token`; token checks
use constant-time comparisons. Bearer-only requests are unchanged.

## Profile and onboarding

`PATCH /v1/me` updates the authenticated user's `display_name`. The account UI
splits that value into first and last name for editing and joins them with a
space when saving. When an account has a placeholder-name organization, the
account page asks for first name, last name, and organization name; the normal
organization rename operation confirms that organization name.

## Service API keys

API keys store `service_id=vispector`; list responses include it alongside
masked key metadata. The one-time create response remains the only response
containing the full key literal. Local Docker exposes
`GET /v1/local/vispector/protected` outside the public endpoint manifest. It
uses normal API-key authentication and accepts only active Vispector keys.

## Local verification evidence

Suspension follow-up verification passed 82 backend unit/schema tests and Ruff
on changed backend files. UI `npm run check` passed 142 tests and
`npm run test:e2e` passed 48 checks. Docker rebuilt and the API health check
passed with the additive SQLite v5 migration. The API-key integration
regression test was added, but host test collection is blocked because `PyJWT`
is unavailable in that Python environment.

The implementation handoff verified the Docker Compose UI and API images built
and both containers returned HTTP 200. A synthetic Vispector key authenticated
to the protected route, remained valid after restarting the API container,
and was then revoked and rejected. Synthetic records were deleted after the
proof. Focused backend verification passed 186 tests. The complete backend
suite passed 2,086 tests, with 167 DynamoDB Local cases skipped because no
emulator was running. The UI check passed 139 tests, and Playwright passed 48 tests
including the mocked administrator dashboard flow at all three viewports.
Hosted Cognito Managed Login loaded using the development pool and local
callback, but user credentials were not entered; full login and first-login
provisioning therefore remain unverified. Production deployment and live
backend browser behavior are not claimed by this evidence.

Subscription and usage APIs and UI remain out of scope; their existing empty
states are unchanged.
