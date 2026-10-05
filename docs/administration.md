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
AWS Lambda therefore has environment-table-scoped `Scan`, `UpdateItem`, and `DeleteItem`
permissions for these admin actions. The separate operator CLI role does not
receive those permissions.

See [operations.md](operations.md) for safe CLI invocation, migration handling,
and AWS operator permissions.

Use a separate restricted AWS operator role for this CLI. It needs only the
DynamoDB reads required to resolve the user and audit anchor, the conditional
user update and transaction checks, and append-only audit-event writes. It
does not need Lambda execution, Cognito, KMS, API-key pepper, or
table-scan permissions. Keep its table and index grants aligned with the
operations implemented by the CLI.
