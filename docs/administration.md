# Administration

Application-wide administrator privileges are separate from organization
membership roles. `ApplicationRole` is the closed `user` / `admin` vocabulary;
organization roles are `viewer`, `member`, `org_admin`, and `owner`.

## Operator bootstrap

Operators grant or revoke application-admin status with
`python -m feednow_auth.admin grant|revoke --email <address>`. The target user
must already exist. The service resolves the email explicitly and refuses an
ambiguous match. The storage transition atomically updates the role and appends
the corresponding audit event; demoting the last active administrator is
rejected. There is no default administrator, startup-time promotion, or
production HTTP bootstrap route.

The global-admin dependency protects organization-administration routes in
both local Docker and the AWS Lambda runtime. Both compositions use the same
router over their configured storage adapter.

The CLI exits with `0` for success (including idempotent already-granted or
already-revoked results), `1` for an unexpected failure, `2` for invalid
arguments or unusable storage configuration, `3` when no user matches the
email, `4` when the email is ambiguous, and `5` when revoking would remove the
last active administrator. `list` reports persisted account status, role, and
registration date; last login is shown as `not recorded` because it is not
stored.

## Vispector onboarding outbox

`onboarding-status --organization-id <org_id>` prints the durable request ID,
bootstrap version, state, attempt count, update time, and sanitized last error.
`onboarding-retry --organization-id <org_id>` immediately retries that request
without requiring another user login. It uses `FEEDNOW_VISPECTOR_URL` and the
call-time `FEEDNOW_VISPECTOR_SERVICE_SECRET`; the credential is never printed
or persisted. Supply the credential through the operator's approved secret
manager when invoking the command, not through shell history. A missing outbox
record exits with code 6; failed dispatch exits with code 1 and leaves a
retryable failure state.

## Organization lifecycle

The admin API supports organization summary/search/detail/member reads,
suspend, reactivate, and confirmed delete. These routes use the authenticated
backend user's application role and the `LocalAdminStorage` extension, which
is implemented by both SQLite and DynamoDB adapters. Suspension records its
first timestamp and revokes the organization's API keys while preserving its
members. Reactivation restores organization access but does not restore revoked
keys. Deletion requires the exact organization name. SQLite performs deletion
atomically; DynamoDB removes related records with multiple writes and may leave
the organization partially cleaned up if storage fails during the operation.
An application administrator who owns an organization cannot suspend or
delete it. Search and detail responses mark the current administrator's owned
organization so the account UI can replace its actions menu with an ownership
badge; the API enforces the same restriction for direct requests.
Application administrators can independently enable or disable an
organization through the admin API. This flag is separate from suspension:
disabling leaves memberships, keys, and data intact while shared authorization
rejects both session and API-key requests. Demo-type organizations are marked
with the `demo` type and the account UI exposes their enabled state and an
enable/disable action.
AWS Lambda therefore has environment-table-scoped `Scan`, `UpdateItem`, and `DeleteItem`
permissions for these admin actions. The separate operator CLI role does not
receive those permissions.

See [operations.md](operations.md) for safe CLI invocation, migration handling,
and AWS operator permissions.

Use a separate restricted AWS operator role for this CLI. Existing
application-role commands need DynamoDB reads to resolve users and the audit
anchor, conditional updates and transaction checks, and append-only audit-event
writes. Demo lifecycle commands additionally need organization search and
cleanup permissions plus the Cognito pool inspection and admin-user operations
documented in [operations.md](operations.md). Keep those Cognito grants limited
to demo operators. The role does not need Lambda execution, KMS, or API-key
pepper access.


## Managed demo organizations

Use `scripts/feednow-admin.sh demo create --name NAME [--slug SLUG]` with an
explicit AWS `--profile` and `--env` to create a demo organization and its
independent Cognito identity in the existing pool. The organization slug is a
stable FeedNow handle. For pools configured with email sign-in, Cognito login
uses the synthetic identifier `<slug>@demo.feednow.io`; it is marked verified
for sign-in and does not require a mailbox. FeedNow atomically provisions the
user, demo organization, membership, audit events, and the same Vispector
onboarding outbox used for a standard first-time user. The CLI immediately
dispatches that request when `FEEDNOW_VISPECTOR_URL` and
`FEEDNOW_VISPECTOR_SERVICE_SECRET` are configured. If dispatch is unavailable,
the request remains retryable with `onboarding-retry --organization-id <org_id>`.
The CLI prints the login and independently generated password once after
provisioning succeeds. FeedNow does not persist the password. In
username-sign-in pools, the slug remains the Cognito login.

`demo list` shows organization names, login identifiers, and enabled state.
`demo reset-password --org SLUG` generates and sets a new permanent password
for that demo organization's managed login, then displays it once. The old
password stops working immediately, and FeedNow does not persist either
password. Use this command when a demo credential needs rotation; it applies
only to the managed owner login of an organization marked as a demo.
`demo delete --org SLUG` removes the Cognito identity and demo organization
data, and is intentionally available only through the operator CLI. The admin
account UI can identify demo tenants and enable or disable them, but does not
create logins or reveal passwords. Disabling is the access kill switch: common
session and API-key authorization checks resolve the current organization and
reject it while disabled.

The operator role needs Cognito `DescribeUserPool`,
`DescribeUserPoolClient`, `AdminGetUser`, `AdminCreateUser`,
`AdminSetUserPassword`, and `AdminDeleteUser`, in addition to its existing
FeedNow storage permissions. The ordinary account-UI admin role receives no
Cognito permissions.
