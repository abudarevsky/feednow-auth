# Phase 16 — FeedNow Auth Dev/Prod Environment Separation and AWS Deployment

**Status:** active, authorized by the user on 2026-10-01.

> Full accepted source requirements are tracked in
> `specs/draft/16-dev-prod-environment-separation-and-aws-deployment.md`.

# FeedNow Auth — Dev/Prod Environment Separation and AWS Deployment Specification

## 1. Objective

Deploy the currently working `feednow-auth` application to AWS while preserving local development and creating an isolated production environment.

The environments are:

- `dev`
- `staging` — supported by tooling, deployment optional
- `prod`

Development continues to run locally through the existing `run-dev.sh`.

Production runs in AWS using:

- the existing, user-provisioned production Cognito User Pool and app client, imported without replacement;
- separate production application resources;
- separate production data;
- `account.feednow.io`.

The same application code and Docker image should be usable in development and production.

---

# 2. Existing Scripts

## `run-dev.sh`

Keep the existing `run-dev.sh` as the local-development entry point.

```bash
./run-dev.sh
```

It starts the local Docker environment and uses the existing development configuration and `feednow-auth-dev` Cognito environment.

Do not move local development lifecycle management into the AWS deployment tooling.

---

## `scripts/feednow-admin.sh`

Preserve the existing administration CLI:

```text
scripts/feednow-admin.sh [--profile AWS_PROFILE] [--env dev|staging|prod] grant --email ADDRESS
scripts/feednow-admin.sh [--profile AWS_PROFILE] [--env dev|staging|prod] revoke --email ADDRESS
scripts/feednow-admin.sh [--profile AWS_PROFILE] [--env dev|staging|prod] list
```

Its responsibility remains FeedNow user/administrator operations.

---

# 3. `--profile` — AWS CLI Profile

`--profile` has exactly the same meaning as the standard AWS CLI option:

```bash
aws --profile AWS_PROFILE ...
```

For example:

```bash
scripts/feednow-admin.sh \
  --profile my-aws-profile \
  --env prod \
  list
```

must execute AWS operations using the equivalent of:

```bash
aws --profile my-aws-profile ...
```

or:

```bash
AWS_PROFILE=my-aws-profile
```

where required by CDK or child processes.

`--profile`:

- identifies a standard AWS CLI named profile;
- obtains its configuration from the standard AWS CLI configuration mechanism;
- must not load a FeedNow `.env` file;
- must not represent `dev`, `staging`, or `prod`;
- must not contain FeedNow-specific semantics.

AWS credentials and AWS profile configuration remain under the normal AWS CLI configuration, typically:

```text
~/.aws/config
~/.aws/credentials
```

Do not create a custom FeedNow profile mechanism.

---

# 4. `--env` — FeedNow Environment

`--env` selects the FeedNow deployment environment:

```text
dev
staging
prod
```

For example:

```bash
scripts/feednow-admin.sh \
  --profile my-aws-profile \
  --env prod \
  list
```

means:

```text
AWS credentials:
    standard AWS profile "my-aws-profile"

FeedNow environment:
    prod
```

These are independent dimensions.

The same AWS profile may be used for multiple FeedNow environments if they are deployed into the same AWS account.

---

# 5. FeedNow Environment Configuration

FeedNow environment configuration is stored under:

```text
deploy/aws/cdk/
```

using:

```text
.env.dev
.env.staging
.env.prod
```

The selected `--env` determines the configuration file:

```text
--env dev
    → deploy/aws/cdk/.env.dev

--env staging
    → deploy/aws/cdk/.env.staging

--env prod
    → deploy/aws/cdk/.env.prod
```

These are **environment files**, not AWS profile files.

They must not contain AWS access keys or AWS CLI credentials.

Example:

```text
FEEDNOW_ENV=prod

AWS_REGION=eu-north-1
AWS_ACCOUNT_ID=123456789012

STACK_NAME=feednow-auth-prod

FEEDNOW_COGNITO_USER_POOL_ID=eu-north-1_<existing-pool-suffix>
FEEDNOW_COGNITO_CLIENT_ID=<existing-public-client-id>

ACCOUNT_BASE_URL=https://account.feednow.io
VISPECTOR_BASE_URL=https://vispector.feednow.io
```

Generated AWS identifiers should preferably be obtained from CDK outputs rather than duplicated manually.

---

# 6. Resolution Model

For an operation such as:

```bash
scripts/feednow-admin.sh \
  --profile work \
  --env prod \
  list
```

resolution is:

```text
--profile work
      │
      └── standard AWS CLI profile
          ~/.aws/config / ~/.aws/credentials

--env prod
      │
      └── FeedNow environment
          deploy/aws/cdk/.env.prod
```

The resulting operation is:

```text
AWS credentials from "work"
          +
FeedNow production configuration
          ↓
production FeedNow AWS resources
```

Do not derive one from the other.

---

# 7. AWS/CDK Deployment

Use the existing CDK implementation and parameterize it by FeedNow environment.

A deployment command should conceptually support:

```bash
deploy/aws/deploy.sh \
  --profile AWS_PROFILE \
  --env prod \
  diff
```

and:

```bash
deploy/aws/deploy.sh \
  --profile AWS_PROFILE \
  --env prod \
  deploy
```

If an appropriate deployment script already exists, extend it instead of introducing another script.

Internally:

- `--profile` is passed to AWS/CDK as the AWS profile;
- `--env` determines `.env.<env>` and CDK environment configuration.

For example:

```text
deploy --profile work --env prod
             │            │
             │            └── .env.prod
             │
             └── AWS CLI profile "work"
```

---

# 8. Target Environments

Target separation:

```text
                    DEV                       PROD

Runtime             local Docker              AWS

Launcher            run-dev.sh                AWS deployment CLI

Cognito             feednow-auth-dev          feednow-auth-prod

Google OAuth        dev client                prod client

FeedNow data        dev                       prod

API keys            dev                       prod

Account URL         localhost                 account.feednow.io

Vispector           local/dev                 vispector.feednow.io
```

`staging` should be supported structurally but does not have to be deployed in this phase.

---

# 9. Cognito Separation

Preserve:

```text
feednow-auth-dev
```

Use the user-provisioned production pool and app client. CDK imports their IDs and never creates or replaces Cognito resources.

using the same parameterized CDK implementation.

They must have independent:

- User Pools;
- App Clients;
- users;
- Cognito domains;
- Google IdP configuration;
- callback URLs;
- logout URLs;
- attribute mappings;
- Lambda triggers.

Do not migrate development users automatically.

---

# 10. Protect Existing Development

The current `feednow-auth-dev` environment is already working and must be preserved.

Before deploying the parameterized infrastructure:

1. Inspect existing AWS resources.
2. Compare them with CDK definitions.
3. Run CDK diff for `dev`.
4. Verify the existing User Pool is not replaced.
5. Verify the existing App Client is not unexpectedly replaced.
6. Preserve existing users.

Creating production must not modify development resources.

---

# 11. Google OAuth

Use separate Google OAuth clients:

```text
FeedNow Auth Dev
FeedNow Auth Prod
```

Production uses the production Cognito callback:

```text
https://<prod-cognito-domain>/oauth2/idpresponse
```

Development and production Google credentials must be independent.

---

# 12. Secret Management

## Do not use AWS Secrets Manager

AWS Secrets Manager is explicitly outside the architecture.

Do not:

- create Secrets Manager resources;
- use Secrets Manager CDK constructs;
- introduce Secrets Manager runtime dependencies;
- store Google OAuth credentials in Secrets Manager.

AWS credentials remain managed through standard AWS CLI profiles.

Application/provider secrets must not be committed to Git or embedded into Docker images.

The API-key pepper must not be stored in SSM Parameter Store either. The
operator encrypts it with the environment's CDK-managed KMS key and supplies
only base64 ciphertext in the Lambda environment. The runtime decrypts it with
an environment-specific encryption context and caches plaintext in memory for
the Lambda container lifetime. Plaintext must not be written to Git, Docker,
CloudFormation templates, environment files, logs, or shell output.

---

# 13. Google Credential Rotation

Provide an operational mechanism for updating the Google OAuth credentials used by Cognito.

The command should accept the standard AWS profile and FeedNow environment independently.

Conceptually:

```bash
deploy/aws/feednow-auth.sh \
  --profile work \
  --env prod \
  rotate-google-credentials
```

The exact script should follow existing repository conventions.

The operation must:

1. Resolve `.env.prod` from `--env prod`.
2. Use standard AWS CLI profile `work`.
3. Determine the correct production Cognito resources.
4. Accept the new Google credential securely.
5. Update the Cognito Google IdP.
6. Never echo the secret.
7. Never write the secret into Git-tracked configuration.
8. Report successful update without revealing the secret.

Creation/rotation of the credential on Google's side may remain a manual Google Console operation.

---

# 14. Production Safety

Before an AWS-changing production operation, show non-sensitive target information:

```text
FeedNow environment: prod
AWS profile:         work
AWS account:         123456789012
AWS region:          eu-north-1
Stack:               feednow-auth-prod
Cognito pool:        feednow-auth-prod
```

Verify the actual AWS identity using the standard profile:

```bash
aws sts get-caller-identity \
  --profile work
```

Compare the returned account ID with the expected account for the selected FeedNow environment.

Fail on mismatch.

Also fail on:

- unknown `--env`;
- missing `.env.<env>`;
- invalid AWS profile;
- unexpected AWS account;
- missing required environment configuration.

Never silently fall back to production.

---

# 15. Data Separation

Development and production must use separate FeedNow application data.

Separate:

- users;
- organizations;
- organization membership;
- permissions;
- API keys.

Production and development must not share an API-key store.

Use environment-qualified resource names where practical:

```text
feednow-auth-dev-...
feednow-auth-prod-...
```

---

# 16. API-Key Isolation

API keys remain application credentials owned by `feednow-auth`.

Development API keys must not work against production.

Production Vispector:

```text
vispector.feednow.io
        │
        ▼
production FeedNow API-key validation
        │
        ▼
production organization/user/service context
```

Local/development Vispector uses development API-key data only.

---

# 17. Production Domain

Production FeedNow Auth is exposed as:

```text
https://account.feednow.io
```

AWS infrastructure provides:

```text
DNS
 ↓
ACM certificate
 ↓
AWS application endpoint
 ↓
feednow-auth
```

TLS certificates should be managed through ACM.

---

# 18. Production Authentication

Target browser flow:

```text
vispector.feednow.io
        │
        ▼
account.feednow.io
        │
        ▼
feednow-auth-prod Cognito
        │
        ▼
Google / Cognito authentication
        │
        ▼
FeedNow user/account resolution
        │
        ▼
FeedNow session
        │
        ▼
vispector.feednow.io
```

Return URLs must be validated against configured FeedNow service origins.

---

# 19. Production Administrator Bootstrap

Do not create a hard-coded production superuser.

Register the first production account through the normal authentication flow.

Then use the existing CLI:

```bash
scripts/feednow-admin.sh \
  --profile AWS_PROFILE \
  --env prod \
  grant --email ADDRESS
```

Verify:

```bash
scripts/feednow-admin.sh \
  --profile AWS_PROFILE \
  --env prod \
  list
```

Revoke:

```bash
scripts/feednow-admin.sh \
  --profile AWS_PROFILE \
  --env prod \
  revoke --email ADDRESS
```

---

# 20. Implementation Sequence

1. Capture the existing `feednow-auth-dev` configuration accurately in CDK.

2. Add environment-specific configuration:

```text
deploy/aws/cdk/.env.dev
deploy/aws/cdk/.env.staging
deploy/aws/cdk/.env.prod
```

3. Parameterize CDK by `--env`.

4. Preserve `run-dev.sh` and verify local Docker continues using `feednow-auth-dev`.

5. Preserve `scripts/feednow-admin.sh` semantics:
   - `--profile` = standard AWS CLI profile.
   - `--env` = FeedNow environment.

6. Run a dev CDK diff and verify no existing Cognito resources are unexpectedly replaced.

7. Create the production Google OAuth client.

8. Run production CDK diff using the desired standard AWS CLI profile and `--env prod`.

9. Deploy production application/data resources using the imported production Cognito pool and client; never create or replace Cognito resources.

10. Configure Google credentials without AWS Secrets Manager.

11. Configure ACM and `account.feednow.io`.

12. Verify production authentication.

13. Register the initial production user.

14. Grant administrator permissions with `scripts/feednow-admin.sh`.

15. Connect `vispector.feednow.io` to production FeedNow authentication and API-key validation.

---

# 21. Acceptance Criteria

Local development continues to work through:

```bash
./run-dev.sh
```

The administration CLI remains:

```text
scripts/feednow-admin.sh [--profile AWS_PROFILE] [--env dev|staging|prod] grant --email ADDRESS
scripts/feednow-admin.sh [--profile AWS_PROFILE] [--env dev|staging|prod] revoke --email ADDRESS
scripts/feednow-admin.sh [--profile AWS_PROFILE] [--env dev|staging|prod] list
```

`--profile` is passed to the standard AWS CLI/CDK credential resolution mechanism.

`--profile` has no FeedNow-specific configuration semantics.

`--env` selects the FeedNow environment and `.env.<env>`.

Production uses its user-provisioned `feednow-auth-prod` Cognito User Pool and app client. Deployment imports these resources and never creates or replaces them.

Development and production users, organizations, API keys and application data are isolated.

The existing development Cognito environment is preserved.

AWS Secrets Manager is not used.

Production credentials are not committed to Git.

Production deployment and credential-changing operations verify the AWS account before making changes.

---

# 22. Non-Goals

This phase does not include:

- a custom AWS profile system;
- storing AWS credentials in `.env.<env>`;
- migration of dev users to prod;
- shared Cognito users;
- shared API keys;
- AWS Secrets Manager;
- automatic scheduled credential rotation;
- invitation workflow;
- mandatory staging deployment;
- multi-region deployment;
- redesign of the existing permission model;
- redesign of the working Cognito authentication flow.

The objective is to preserve the existing local development workflow while creating a reproducible and isolated production deployment using standard AWS CLI profiles and explicit FeedNow environments.
