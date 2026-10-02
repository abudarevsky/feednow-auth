# Account application

Local Docker and AWS Lambda provide the account UI's backend surface with
Cognito login, opaque sessions, CSRF protection, and application
administration. Docker uses the configured local storage adapter; AWS uses
DynamoDB. The local Vispector proof route is not part of the production API.

## Account and organization behavior

`GET /v1/me` returns the authenticated user's profile and application role.
`PATCH /v1/me` updates the display name; the account UI joins the edited first
and last names into that field. New personal workspaces are marked
with `name_status=placeholder`; an authorized organization rename confirms
the name while preserving the creation timestamp. Existing local databases
migrate forward to the current SQLite schema.

Application administrators can view summary counts, search organizations
case-insensitively with pagination, inspect organization details and
memberships, suspend or reactivate an organization, and delete it after exact
name confirmation. These operations use the configured storage adapter and
require the backend's global application-admin role. Suspension revokes keys
and blocks organization operations while leaving member accounts available to
sign in. Reactivation does not restore revoked keys.

| Method and route | Behavior |
| --- | --- |
| `GET /v1/admin/summary` | Organization and active-membership counts |
| `GET /v1/admin/organizations` | Case-insensitive search with `q`, `limit`, and opaque `cursor` |
| `GET /v1/admin/organizations/{organization_id}` | Organization, member, service, and masked key details |
| `GET /v1/admin/organizations/{organization_id}/members` | Paginated membership and user facts |
| `POST /v1/admin/organizations/{organization_id}/suspend` | Suspend and revoke organization keys |
| `POST /v1/admin/organizations/{organization_id}/reactivate` | Reactivate the organization; previously revoked keys stay revoked |
| `POST /v1/admin/organizations/{organization_id}/delete` | Delete after exact organization-name confirmation |

## Vispector API keys

New API keys are bound to `service_id=vispector`; masked list/admin summaries
may expose this service identifier. The full credential is returned only in
the successful create response. `GET /v1/local/vispector/protected` is a
local-only proof route outside the public manifest and accepts only a valid,
active Vispector key.

## Limits

Subscription and usage management are not implemented. Local UI or synthetic
key checks do not establish a deployed Vispector integration. Live Cognito and
production behavior must be reported only when those paths have been exercised.
