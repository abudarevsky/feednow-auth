# Phase 07 — AWS infrastructure and deployable runtime

**Dependency:** Phases 03, 05, and 06  
**Handoff to:** Phase 08

## Goal

Provision an environment-separated AWS runtime for Cognito-backed authentication and DynamoDB storage using the established `deploy/aws/cdk` Python CDK layout.

## Work boundary

- Create `deploy/aws/cdk/app.py`, `cdk.json`, CDK Python requirements, a stack module, and `.env.example`, following Vispector's Python CDK entrypoint/stack separation.
- Define CDK constructs for Cognito User Pool/app client/domain/OAuth PKCE, DynamoDB tables/indexes, Secrets Manager, Lambda, API Gateway, CloudWatch, and least-privilege IAM.
- Define isolated dev/staging/prod CDK inputs, naming strategy, secret injection, app configuration, and Lambda/FastAPI packaging. Keep deployment inputs out of application runtime configuration unless explicitly injected by the stack.
- Add infrastructure validation and a non-production deployed smoke-test procedure.

## Acceptance criteria

- CDK Python dependencies install, `cdk synth` succeeds, and stack assertions cover critical resources; environment inputs do not expose plaintext pepper/secrets in source or outputs.
- Cognito supports email/password, verification/reset, and Authorization Code with PKCE.
- Lambda/API Gateway have only required permissions; runtime reads pepper from Secrets Manager and data from DynamoDB.
- CloudWatch provides correlated safe diagnostics with no tokens, passwords, or API secrets.
- A non-production smoke path proves Cognito-authenticated context resolution and first-login provisioning.

## Non-goals

Automatic production deployment, product APIs, and Google/Microsoft/SAML federation.

## Handoff

Record CDK synth/deploy commands, deployment inputs, runtime configuration, smoke evidence, and rollback-safe operational notes.
